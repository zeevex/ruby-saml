require 'libxml'
require 'xmlsec'
require 'time'

module Onelogin::Saml

  class Response
    ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion'
    PROTOCOL  = 'urn:oasis:names:tc:SAML:2.0:protocol'
    DSIG      = 'http://www.w3.org/2000/09/xmldsig#'
    XMLNS     = { 'p' => PROTOCOL, 'a' => ASSERTION, 'ds' => DSIG }

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
        nodes   = @document.find("/p:Response/a:Assertion[@ID='#{signed_element_id}']/a:Subject/a:NameID", XMLNS)
        nodes ||= @document.find("/p:Response[@ID='#{signed_element_id}']/a:Assertion/a:Subject/a:NameID", XMLNS)
        return validation_error("NameId not present") if nodes.nil? or nodes.length == 0
        return validation_error("Too many NameIds (#{nodes.length})") if nodes.length > 1

        name_id = nodes[0].content.strip
        return validation_error("NameId is empty") if name_id.empty?

        name_id
      end
    end

    # A hash of all the attributes in the response. Assumes there is only one value for each key
    def attributes
      @attr_statements ||= begin
        result = {}

        attrs = @document.find("/p:Response/a:Assertion/a:AttributeStatement/a:Attribute", XMLNS)
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
        nodes = @document.find("/p:Response/a:Assertion/a:AuthnStatement", XMLNS)
        nodes.length > 0 ? parse_time(nodes, "SessionNotOnOrAfter") : nil
      end
    end

    # Conditions (if any) for the assertion to run
    def conditions
      @conditions ||= @document.find("/p:Response/a:Assertion[@ID='#{signed_element_id}']/a:Conditions", XMLNS)
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

    # Assertions or Responses have IDs that should be used to
    # reference them.  Signed responses have the ID in the Signature's
    # Reference URI.  If we're not checking signatures, look for it in
    # the Assertion first, then the Response.
    def signed_element_id
      @signed_element_id ||=
        begin
          # FIXME: support for unsigned responses. Needs support from the app settings, disable for now.
          # Also consider not ever support unsigned responses.  Ie., yank this code!
          # if settings.signed_idp_responses
            references = @document.find("//ds:Signature/ds:SignedInfo/ds:Reference", XMLNS)
            return validation_error('No Reference node') if references.nil? or references.length == 0

            uris = references.map { |node| node.attributes['URI'] }.compact
            return validation_error('Reference node has no URI') if uris.nil? or uris.length == 0

            # FIXME: placeholders for handling multiple Reference nodes.  Jus use the first node for now.
            # ideally, we'd pick the URI of the Assertion node, if any, over the Response node.
            # signable_paths = ["/p:Response/a:Assertion[@ID='#{uri}']", "/p:Response[@ID='#{uri}']"]

            uri = uris.first

            # The URI should be a self-reference with a leading '#'
            return validation_error("URI is not local: #{uri}") if uri[0] != ?#

            # The ID is all but the leading '#'
            uri[1,uri.length]
          # else
          #   nodes   = @document.find("/p:Response/a:Assertion[@ID]", XMLNS)
          #   nodes ||= @document.find("/p:Response[@ID]", XMLNS)
          #   return validation_error('No Response or Assertion node with ID') if nodes.nil? or nodes.length == 0
          #   return validation_error("Too many Response/Assertion ID nodes: #{nodes.length}") if nodes.length > 1

          #   id_value = nodes.first.attributes['ID']
          #   return validation_error('ID node has no ID!') if id_value.nil? or id_value.length == 0

          #   id_value
          # end
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
        return validation_error("Too many nodes (#{nodes.length}) when parsing time for #{attribute}")
      end

      if nodes[0].attributes.include? attribute
        return Time.parse(nodes[0].attributes[attribute])
      end
    end
  end
end
