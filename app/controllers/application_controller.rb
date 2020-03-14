class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  # protect_from_forgery with: :exception
  protect_from_forgery with: :null_session

  def authenticate
    email_auth = request.headers["X-User-Email"]
    token_auth = request.headers["X-Api-Token"]
    head 401 unless User.find_by_email(email_auth) && User.find_by_api_token(token_auth)
  end

end
