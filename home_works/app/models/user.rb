# == Schema Information
#
# Table name: users
#
#  id              :integer          not null, primary key
#  username        :string
#  password_digest :string
#  session_token   :string
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#

class User < ApplicationRecord
  require 'bcrypt'
  validates :password_digest, presence: true, { message: 'Password cannot be blank' }
  validates :username, presence: true, uniqueness: true
  validates :session_token, presence: true, uniqueness: true
  validates :password, length: { minimum: 6, allow_nil: true }
  before_validation :ensure_session_token



  attr_reader :password


def self.find_by_credentials(username, password)
    user = User.find_by(username: username)
    return nil if user.nil?
    user.is_password?(password) ? user : nil
end

def self.generate_session_token
   SecureRandom::urlsafe_base64(16)
end

def reset_session_token!
  self.session_token = self.class.generate_session_token
  self.save!
  self.session_token
end

def password=(password)
  @password = password
  self.password_digest = Bcrypt::Password.create(password)
end

private

def ensure_session_token
   self.session_token ||= self.class.generate_session_token
end

end
