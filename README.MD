#### Front End App

[Auth Workflow](https://react-node-user-workflow-front-end.netlify.app/)

#### Update User Model

- [X] add following three properties
- [X] verificationToken - String
- [X] isVerified - {type:Boolean, default:false}
- [X] verified - Date

#### Update Register Controller

- [X] setup fake verificationToken - 'fake token'
- [X] remove everything after User.create()
- [X] send back success message and token

#### Update Login Controller

- [X] right after isPasswordCorrect
- [X] check if user.isVerified, if not 401

#### Verify Email Controller

- [X] create verifyEmail in authController
- [X] get verificationToken and email from req.body
- [X] setup a '/verify-email' route in authRoutes
- [X] test in a Postman
- [X] check for user using email
- [X] if no user 401
- [X] if token does not match user token 401
- [X] if correct set
- [X] user.isVerified = true
- [X] user.verified = Date.now()
- [X] user.verificationToken = ''
- [X] save use with instance method
- [X] return msg:'email verified'

#### Email Setup

- [X] re-watch project 08
- [X] ethereal credentials (create account/login)
- [X] install nodemailer
- [X] create (nodemailerConfig, sendEmail,
  sendResetPasswordEmail, sendVerficationEmail) files in utils

#### Send Verification Link

- [X] refactor sendEmail
- [X] setup sendVerificationEmail.js
- [X] pass arguments

#### Token Model

- [X] create Token.js in models
- [X] refreshToken,ip,userAgent - all String and required
- [X] isValid - Boolean, default:true
- [X] ref user
- [X] timestamps true

#### Setup Token in Login Controller

#### Send Multiple Cookies

#### Check for Existing Token

#### Refactor Auth Middleware - Access , Refresh Token

#### Logout

#### Forgot/Reset Password Functionality

- User Model
- passwordToken {type:String}
- passwordTokenExpirationDate {type:Date}
- authController
- forgotPassword and resetPassword
- authRoutes
- post '/forgot-password' '/reset-password'

#### Forgot Password Controller

#### Send Reset Password Email

#### Reset Password Controller

#### Hash Password Token
