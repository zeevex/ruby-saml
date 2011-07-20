require 'base64'
require 'uuid'
require 'zlib'
require 'cgi'
require 'libxml'
require 'xmlsec'

module Onelogin::Saml
  class Authrequest
    DSIG    = 'http://www.w3.org/2000/09/xmldsig#'
    CMETHOD = 'http://www.w3.org/2001/10/xml-exc-c14n#'

    def initialize(request_id = nil)
      @request_id = request_id || '_' + UUID.new.generate
    end

    # return redirect_to URL for HTTP-REDIRECT binding
    def create(settings, params = {})
      request          = authrequest(settings)
      deflated_request = Zlib::Deflate.deflate(request, 9)[2..-5]
      base64_request   = Base64.encode64(deflated_request)
      encoded_request  = CGI.escape(base64_request)
      request_params   = '?SAMLRequest=' + encoded_request

      params.each_pair do |key, value|
        request_params << "&#{key}=#{CGI.escape(value.to_s)}"
      end

      settings.idp_sso_target_url + request_params
    end

    # return encoded request for HTTP-POST binding
    def encoded_POST_request(settings)
      request        = authrequest(settings)
      base64_request = Base64.encode64(request)

      base64_request
    end

    private

    def authrequest(settings)
      time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

      head =
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"#{@request_id}\" Version=\"2.0\" IssueInstant=\"#{time}\" Destination=\"#{settings.idp_sso_target_url}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"#{settings.assertion_consumer_service_url}\">" +
        "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{settings.issuer}</saml:Issuer>" +
        "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"#{settings.name_identifier_format}\" AllowCreate=\"true\"></samlp:NameIDPolicy>" +
        "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
        "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>"

      # leave a hole for the signature to slot in
      tail = "</samlp:AuthnRequest>"

      if settings.sign_authn_reqs
        template = head + signature_template(@request_id, settings.sp_x509_certificate) + tail
        document = LibXML::XML::Parser.string(template).parse
        Xmlsec.sign_document(document, settings.sp_private_key)

        # disable indentation, it invalidates the digest in the signature
        request = document.to_s(:indent => false)
      else
        request = head + tail
      end
    end

    def signature_template(uri, certificate)
      cert_der  = OpenSSL::X509::Certificate.new(certificate).to_der

      signature_template =
        "<ds:Signature xmlns:ds=\"#{DSIG}\">" +
          "<ds:SignedInfo xmlns:ds=\"#{DSIG}\">" +
            "<ds:CanonicalizationMethod Algorithm=\"#{CMETHOD}\"/>" +
            "<ds:SignatureMethod Algorithm=\"#{DSIG}rsa-sha1\"/>" +
            # the Signature's Reference node must have a URI attribute with
            # the signed entity's ID value.
            "<ds:Reference URI=\"##{uri}\">" +
              "<ds:Transforms>" +
                "<ds:Transform Algorithm=\"#{DSIG}enveloped-signature\"/>" +
                "<ds:Transform Algorithm=\"#{CMETHOD}\"/>" +
              "</ds:Transforms>" +
              "<ds:DigestMethod Algorithm=\"#{DSIG}sha1\"/>" +
              # DigestValue will be filled in by xmlsec
              "<ds:DigestValue />" +
            "</ds:Reference>" +
          "</ds:SignedInfo>" +
          # SignatureValue will be filled in by xmlsec
          "<ds:SignatureValue />" +
          "<ds:KeyInfo>" +
            "<ds:X509Data>" +
              "<ds:X509Certificate>" +
                "#{Base64.encode64(cert_der)}" +
              "</ds:X509Certificate>" +
            "</ds:X509Data>" +
          "</ds:KeyInfo>" +
        "</ds:Signature>"

      return signature_template
    end
  end
end
