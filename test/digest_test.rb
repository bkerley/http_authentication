require 'test/unit'
$LOAD_PATH << File.dirname(__FILE__) + '/../lib/'
require 'http_authentication'

class HttpDigestAuthenticationTest < Test::Unit::TestCase
  include HttpAuthentication::Digest
  
  def setup
    @controller = Class.new do
      attr_accessor :headers, :renders
      
      def initialize
        @headers, @renders = {}, []
      end
      
      def request
        Class.new do
          def env
            { 'HTTP_AUTHORIZATION' => HttpAuthentication::Digest.encode_credentials("dhh", "secret") }
          end
        end.new
      end
      
      def render(options)
        self.renders << options
      end
    end.new
  end

  def test_authentication_request
    authentication_request(@controller, 'Megaglobalapp')
		auth_header = @controller.headers['WWW-Authenticate']
    assert auth_header.include? 'realm="Megaglobalapp"'
		assert auth_header.include? 'nonce='
		assert auth_header.include? 'opaque='
    assert_equal :unauthorized, @controller.renders.first[:status]
  end

	def test_encode_credentials
	  authentication_request(@controller, 'Megaglobalapp')
	  auth_response_string = @controller.headers['WWW-Authenticate'].gsub('Digest ','')
	  auth_responses = parse_auth_string(auth_response_string)
    # headers = @controller.request.env
	  
	  assert_equal '"Megaglobalapp"', auth_responses['realm']
	  
  end
end
