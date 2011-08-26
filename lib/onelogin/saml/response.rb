require 'libxml'
require 'xmlsec'
require 'time'

module Onelogin::Saml

  class Response
    # XML namespaces used in a SAML 2.0 response
    ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion'
    PROTOCOL  = 'urn:oasis:names:tc:SAML:2.0:protocol'
    DSIG      = 'http://www.w3.org/2000/09/xmldsig#'
    XMLNS     = { 'p' => PROTOCOL, 'a' => ASSERTION, 'ds' => DSIG }

    # Select StatusCode values
    SC_SUCCESS     = 'urn:oasis:names:tc:SAML:2.0:status:Success'
    SC_AUTHNFAILED = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'

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
      validate_signature      &&
      validate_status_codes   &&
      validate_timestamps
    end

    # The value of the user identifier as designated by the initialization request response
    def name_id
      @name_id ||= begin
        nodes   = @document.find("/p:Response/a:Assertion/a:Subject/a:NameID", XMLNS)
        return validation_error("NameId not present") if nodes.nil? or nodes.length == 0
        return validation_error("Too many NameIds (#{nodes.length})") if nodes.length > 1

        name_id = nodes.first.content.strip
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

          result[name] = value
        end

        result
      end
    end

    # Expiry time for this session.  Returns nil if not specified.
    def session_expires_at
      @session_expires_at ||= begin
        nodes = @document.find("/p:Response/a:Assertion/a:AuthnStatement", XMLNS)
        return nil if nodes.nil?

        # Use the earliest time
        nodes.map {|n| Time.parse(n.attributes['SessionNotOnOrAfter']) }.min
      end
    end

    # top-level StatusCode in message
    def status_code
      status_codes[:top]
    end

    # array nested StatusCodes within top-level StatusCode, if any
    def sub_status_codes
      status_codes[:sub] || []
    end

    def authn_failed?
      status_code == SC_SUCCESS and sub_status_codes.include?(SC_AUTHNFAILED)
    end

    # The ID of the SAMLRequest that led to this Response
    def in_response_to
      @in_response_to ||= begin
        # InResponseTo can be an attribute of SubjectConfirmationData or Response
        nodes   = @document.find("/p:Response[@InResponseTo]", XMLNS)
        nodes ||= @document.find("/p:Response/a:Assertion/a:Subject/a:SubjectConfirmation/a:SubjectConfirmationData[@InResponseTo]", XMLNS)
        return validation_error('Response missing InResponseTo') if nodes.nil? or nodes.length == 0

        # Use the first node if multiple nodes are present
        nodes.first.attributes['InResponseTo']
      end
    end

    private

    # The SAML StatusCode elements in this message
    # Returns a hash with
    #  :top => top level StatusCode
    #  :sub => StatusCodes within :top, if any
    def status_codes
      @status_codes ||= begin
        top = @document.find("/p:Response/p:Status/p:StatusCode", XMLNS)
        return validation_error('No StatusCode element') if top.nil? or top.length == 0
        return validation_error('Too many top-level StatusCode elements') if top.length > 1

        result = { :top => top.first.attributes['Value'] }

        # since we know that there's only one top level StatusCode, gather any subcodes in one fell swoop
        subcodes = @document.find("/p:Response/p:Status/p:StatusCode/p:StatusCode", XMLNS)
        result[:sub] = subcodes.map { |n| n.attributes['Value'] } unless subcodes.nil? or subcodes.length == 0

        result
      end
    end

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

    # Validates the XML Signature on the SAML Response.
    # Also captures the name and IDs of the elements that have been signed.
    def validate_signature
      sigs = @document.find("//ds:Signature/ds:SignedInfo/ds:Reference", XMLNS)
      return validation_error('No Signature Reference node') if sigs.nil? or sigs.length == 0

      sig_valid = Xmlsec.verify_document(@document, @settings.idp_cert)
      return validation_error('Signature does not verify') unless sig_valid

      # Capture the IDs of elements that were signed
      uris = sigs.map { |node| node.attributes['URI'] }.compact
      return validation_error('Reference node has no URI') if uris.nil? or uris.length == 0

      @signed_element_ids = uris.map do |uri|
        # The URI should be a self-reference with a leading '#'
        return validation_error("Reference URI is not local: #{uri}") if uri[0] != ?#

        # The ID is all but the leading '#'
        uri[1,uri.length]
      end

      # verify that at least one of Response or Assertion is a signed element
      is_signed = @signed_element_ids.any? do |uri|
        nodes   = @document.find("/p:Response[@ID='#{uri}']", XMLNS)
        nodes ||= @document.find("/p:Response/a:Assertion[@ID='#{uri}']", XMLNS)
        !nodes.nil? and nodes.length > 0
      end
      return validation_error('Neither Response nor Assertion node is signed') unless is_signed

      true
    end

    # Validates top-level StatusCode, app must verify subcodes if any
    def validate_status_codes
      return true if status_code == SC_SUCCESS
      return validation_error("Top-level StatusCode is #{status_codes[:top].inspect} (tree is #{status_codes.inspect}")
    end

    def validate_timestamps
      return true if status_code != SC_SUCCESS or sub_status_codes.length > 0

      # NotBefore & NotOnOrAfter may be in two locations and multiple nodes
      timestamp_paths = [
        '/p:Response/a:Assertion/a:Conditions',
        '/p:Response/a:Assertion/a:Subject/a:SubjectConfirmation/a:SubjectConfirmationData',
      ]

      timestamp_paths.each do |xpath|
        nodes = @document.find(xpath, XMLNS)
        nodes.each do |node|
          not_before      = node.attributes['NotBefore']
          not_on_or_after = node.attributes['NotOnOrAfter']
          now             = Time.now.utc

          if !not_before.nil? and now < Time.parse(not_before)
            return validation_error("Current time (#{now}) is NotBefore (#{not_before}")
          end

          if !not_on_or_after.nil? and now >= Time.parse(not_on_or_after)
            return validation_error("Current time (#{now}) is NotOnOrAfter (#{not_on_or_after})")
          end
        end
      end

      true
    end
  end
end
