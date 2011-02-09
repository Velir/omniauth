require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    # Authenticate to Facebook utilizing OAuth 2.0 and retrieve
    # basic user information.
    #
    # @example Basic Usage
    #   use OmniAuth::Strategies::Facebook, 'client_id', 'client_secret'
    class Velir < OAuth2
      # @param [Rack Application] app standard middleware application parameter
      # @param [String] client_id the application id as [registered on Facebook](http://www.facebook.com/developers/)
      # @param [String] client_secret the application secret as registered on Facebook
      # @option options [String] :scope ('email,offline_access') comma-separated extended permissions such as `email` and `manage_pages`
      def initialize(app, client_id = nil, client_secret = nil, options = {}, &block)
        super(app, :velir, client_id, client_secret, {:site => 'http://id.ruby.velir.com/'}, options, &block)
      end
      
      def user_data
        @data ||= MultiJson.decode(@access_token.get('/oauth/user', {}, { "Accept-Language" => "en-us,en;"}))
      end
            
      def user_info
        {
          'email' => (user_data["email"] if user_data["email"])
        }
      end
      
      def auth_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => user_data['id'],
          'user_info' => user_info,
          'extra' => {'user_hash' => user_data}
        })
      end
    end
  end
end