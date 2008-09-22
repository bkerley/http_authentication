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
            blank_env = {'REQUEST_METHOD' => 'GET', 'REQUEST_URI'    => '/ready/to/rumble.js'}
            full_env = HttpAuthentication::Digest.encode_credentials('dhh', 'Megaglobalapp', 'secret', blank_env)
            return populated_env
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
    assert auth_header.include?('realm="Megaglobalapp"')
		assert auth_header.include?('nonce=')
		assert auth_header.include?('opaque=')
    assert_equal :unauthorized, @controller.renders.first[:status]
  end

	def test_encode_credentials
	  authentication_request(@controller, 'Megaglobalapp')
	  auth_response_string = @controller.headers['WWW-Authenticate']
	  auth_responses = parse_auth_string(auth_response_string)
    # headers = @controller.request.env
	  
	  assert_equal 'Megaglobalapp', auth_responses['realm']
	  
	  ha1 = HA1('dhh', 'Megaglobalapp', 'secret')
	  ha2 = HA2('GET', '/ready/to/rumble')
	  
	  # > echo -n "dhh:Megaglobalapp:secret" | openssl md5
    # 98483ce6fb0720a5e42e513ebf3f4017
    # > echo -n "GET:/ready/to/rumble" | openssl md5
    # 47db90657b40465681cda1f8595e6db2
	  assert_equal '98483ce6fb0720a5e42e513ebf3f4017', ha1
	  assert_equal '47db90657b40465681cda1f8595e6db2', ha2
	  
	  credential_string = encode_credentials('dhh', 'secret', auth_response_string, 'GET', '/ready/to/rumble')
    credentials = parse_auth_string(credential_string)
	  assert_equal '00000001', credentials['nc']
	  assert_equal auth_responses['nonce'], credentials['nonce']
	  assert credentials['cnonce']
	  assert_equal 'auth', credentials['qop']
	  
	  assert_equal response_digest(ha1, credentials['nonce'], credentials['nc'], credentials['cnonce'], credentials['qop'], ha2), credentials['response']
  end
end
