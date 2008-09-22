module HttpAuthentication
  module Digest
    module ControllerMethods
      def authenticate_with_http_digest(&login_procedure)
        HttpAuthentication::Digest.authenticate(self, &login_procedure)
      end

      def request_http_basic_authentication(realm = "Application")
        HttpAuthentication::Digest.authentication_request(self, realm)
      end
    end

    extend self
    
    def authenticate(controller, &login_procedure)
      if authorization(controller.request)
        login_procedure.call(*user_name_and_password(controller.request))
      else
        false
      end
    end

    def user_name_and_password(request)
      decode_credentials(request).split(/:/, 2)
    end
  
    def authorization(request)
      request.env['HTTP_AUTHORIZATION']   ||
      request.env['X-HTTP_AUTHORIZATION'] ||
      request.env['X_HTTP_AUTHORIZATION']
    end
  
    def decode_credentials(request)
      # Fancy nouncing goes here
    end

    def encode_credentials(user_name, password)
      # You compute me
    end

    def authentication_request(controller, realm)
      controller.headers["WWW-Authenticate"] = %(Digest #{challenge_response(realm)})
      controller.send(:render, :text => "HTTP Digest: Access denied.\n", :status => :unauthorized)
      return false
    end

		private
		# RFC 2617 3.2.1
		def challenge_response(realm)
			challenge = {'realm'=>realm, 'qop'=>'auth'}
			
			# using a random opaquifier string as a nonce
			# this compromises this against replay attacks
			# since we have no way to know know if we've seen
			# a particular nonce before
			challenge['nonce'] = make_opaque
			challenge['opaque'] = make_opaque
			
			return challenge.map{|k,v| %(#{k}=\"#{v.gsub(/"/, "")}\")}.join(',')
		end
		
		def make_opaque
			Base64.encode64(OpenSSL::Random.random_bytes(30)).strip
		end
  end
end