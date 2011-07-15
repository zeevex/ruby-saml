require 'libxml'
require 'xmlsec'
require 'time'

module Onelogin::Saml

  class Response
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"

    attr_accessor :options, :response, :document, :settings, :soft_errors

    def initialize(response, options = {})
      raise ArgumentError.new("Response cannot be nil") if response.nil?

      self.options     = options
      self.response    = response
      self.soft_errors = true  # don't raise exceptions unless asked to

      saml_response = Base64.decode64(response)
      self.document = LibXML::XML::Parser.string(saml_response).parse
    end

    def is_valid?
      validate_response_state &&
      validate_conditions     &&
      Xmlsec.verify_document(@document, settings.idp_cert)
    end

    # The value of the user identifier as designated by the initialization request response
    def name_id
      @name_id ||= begin
        nodes = @document.find("/p:Response/a:Assertion[@ID='#{signed_element_id}']/a:Subject/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
        nodes ||= @document.find("/p:Response[@ID='#{signed_element_id}']/a:Assertion/a:Subject/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
        return validation_error("NameId not present") if nodes.nil? or nodes.length == 0
        return validation_error("Too many NameIds (#{nodes.length}") if nodes.length > 1

        name_id = nodes[0].content.strip
        return validation_error("NameId is empty") if name_id.empty?

        name_id
      end
    end

    # A hash of all the attributes in the response. Assumes there is only one value for each key
    def attributes
      @attr_statements ||= begin
        result = {}

        attrs = @document.find("/p:Response/a:Assertion/a:AttributeStatement/a:Attribute", { "p" => PROTOCOL, "a" => ASSERTION })
        return {} if attrs.nil? or attrs.length == 0

        attrs.each do |a|
          name  = a.attributes["Name"]
          value = a.children.first.content.strip

          result[name]        = value
          result[name.intern] = value
        end

        result
      end
    end

    # When this user session should expire at latest
    def session_expires_at
      @expires_at ||= begin
        node = @document.find("/p:Response/a:Assertion/a:AuthnStatement", { "p" => PROTOCOL, "a" => ASSERTION })
        node.length > 0 ? parse_time(node, "SessionNotOnOrAfter") : nil
      end
    end

    # Conditions (if any) for the assertion to run
    def conditions
      @conditions ||=
        @document.find("/p:Response/a:Assertion[@ID='#{signed_element_id}']/a:Conditions", { "p" => PROTOCOL, "a" => ASSERTION })
    end

    private

    def validation_error(message)
      return self.soft_errors ? false : raise(ValidationError.new(message))
    end

    def validate_response_state
      if response.empty?
        return validation_error("Blank response")
      end

      if settings.nil?
        return validation_error("No settings on response")
      end

      if settings.idp_cert.nil?
        return validation_error("No certificate on settings")
      end

      true
    end

    def signed_element_id
      @signed_element_id ||=
        begin
          reference = @document.find("//ds:Signature/ds:SignedInfo/ds:Reference", {"ds"=>DSIG})
          return validation_error('No Reference node') if reference.nil? or reference.length == 0
          # This is legal in the general Signature case, but not for our SAML use case
          return validation_error("Too many Reference nodes: #{reference.length}") if reference.length > 1

          uri = reference.first.attributes["URI"]
          return validation_error('Reference node has no URI') if uri.nil? or uri.length == 0

          # The URI should be a self-reference with a leading '#'
          return validation_error("URI is not local: #{uri}") if uri[0] != ?#

          # The ID is all but the leading '#'
          uri[1,uri.length]
        end
    end

    def validate_conditions
      return true if conditions.nil?
      return true if options[:skip_conditions]

      if not_before = parse_time(conditions, "NotBefore")
        if Time.now.utc < not_before
          return validation_error("Current time is earlier than NotBefore condition")
        end
      end

      if not_on_or_after = parse_time(conditions, "NotOnOrAfter")
        if Time.now.utc >= not_on_or_after
          return validation_error("Current time is on or after NotOnOrAfter condition")
        end
      end

      true
    end

    def parse_time(nodes, attribute)
      if nodes.length > 1
        return validation_error("Too many nodes (#{nodes.length} when parsing time for #{attribute}")
      end

      if nodes[0].attributes.include? attribute
        return Time.parse(nodes[0].attributes[attribute])
      end
    end
  end
end
