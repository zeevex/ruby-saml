# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "openssl"
require "onelogin/saml/validation_error"
require "libxml"
require "xmlsec"

module XMLSecurity
  DSIG    = 'http://www.w3.org/2000/09/xmldsig#'
  CMETHOD = 'http://www.w3.org/2001/10/xml-exc-c14n#'

  class UnsignedDocument
    def initialize(head, tail, uri)
      @head = head
      @tail = tail
      @uri  = uri
    end

    def sign(private_key, certificate)
      template = create_template(@head, @tail, @uri, certificate)
      @doc = LibXML::XML::Parser.string(template).parse
      Xmlsec.sign_document(@doc, private_key)
    end

    def to_s(options = nil)
      @doc.to_s(options)
    end

    private

    def create_template(head, tail, uri, certificate)
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

      return head + signature_template + tail
    end
  end
end
