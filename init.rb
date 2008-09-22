ActionController::Base.send :include, HttpAuthentication::Basic::ControllerMethods
ActionController::Base.send :include, HttpAuthentication::Digest::ControllerMethods
