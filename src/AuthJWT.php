<?php

	/*
	 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
	 * Copyright (c) delight.im (https://www.delight.im/)
	 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
	 */

	namespace Delight\Auth;

	use Delight\Base64\Base64;
	use Delight\Cookie\Cookie;
	use Delight\Cookie\Session;
	use Delight\Db\PdoDatabase;
	use Delight\Db\PdoDsn;
	use Delight\Db\Throwable\Error;
	use Delight\Db\Throwable\IntegrityConstraintViolationException;

	require_once __DIR__.'/Exceptions.php';

	/** Component that provides all features and utilities for secure authentication of individual users */
	final class AuthJWT extends UserManager
	{

		const COOKIE_PREFIXES = [Cookie::PREFIX_SECURE, Cookie::PREFIX_HOST];
		const COOKIE_CONTENT_SEPARATOR = '~';

		/** @var string the user's current IP address */
		private $ipAddress;
		/** @var bool whether throttling should be enabled (e.g. in production) or disabled (e.g. during development) */
		private $throttling;
		/** @var int the interval in seconds after which to resynchronize the session data with its authoritative source in the database */
		private $sessionResyncInterval;
		/** @var string the name of the cookie used for the 'remember me' feature */
		private $rememberCookieName;

		public function __construct(
			$databaseConnection,
			$ipAddress = null,
			$dbTablePrefix = null,
			$throttling = null,
			$sessionResyncInterval = null,
			$dbSchema = null
		) {
			parent::__construct($databaseConnection, $dbTablePrefix, $dbSchema);

			$this->ipAddress = !empty($ipAddress) ? $ipAddress : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null);
			$this->throttling = isset($throttling) ? (bool)$throttling : true;
			$this->sessionResyncInterval = isset($sessionResyncInterval) ? ((int)$sessionResyncInterval) : (60 * 5);
			$this->rememberCookieName = self::createRememberCookieName();

			$this->initSessionIfNecessary();
			$this->enhanceHttpSecurity();

			$this->processRememberDirective();
			$this->resyncSessionIfNecessary();
		}

		/** Initializes the session and sets the correct configuration */
		private function initSessionIfNecessary()
		{
		}

		/** Improves the application's security over HTTP(S) by setting specific headers */
		private function enhanceHttpSecurity()
		{
			// remove exposure of PHP version (at least where possible)
			\header_remove('X-Powered-By');

			// if the user is signed in
			if ($this->isLoggedIn()) {
				// prevent clickjacking
				\header('X-Frame-Options: sameorigin');
				// prevent content sniffing (MIME sniffing)
				\header('X-Content-Type-Options: nosniff');

				// disable caching of potentially sensitive data
				\header('Cache-Control: no-store, no-cache, must-revalidate', true);
				\header('Expires: Thu, 19 Nov 1981 00:00:00 GMT', true);
				\header('Pragma: no-cache', true);
			}
		}

		/** Checks if there is a "remember me" directive set and handles the automatic login (if appropriate) */
		private function processRememberDirective()
		{
		}

		private function resyncSessionIfNecessary()
		{
		}

		/**
		 * Attempts to sign up a user
		 * If you want the user's account to be activated by default, pass `null` as the callback
		 * If you want to make the user verify their email address first, pass an anonymous function as the callback
		 * The callback function must have the following signature:
		 * `function ($selector, $token)`
		 * Both pieces of information must be sent to the user, usually embedded in a link
		 * When the user wants to verify their email address as a next step, both pieces will be required again
		 * @param string        $email    the email address to register
		 * @param string        $password the password for the new account
		 * @param string|null   $username (optional) the username that will be displayed
		 * @param callable|null $callback (optional) the function that sends the confirmation email to the user
		 * @return int the ID of the user that has been created (if any)
		 * @throws InvalidEmailException if the email address was invalid
		 * @throws InvalidPasswordException if the password was invalid
		 * @throws UserAlreadyExistsException if a user with the specified email address already exists
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 * @see confirmEmail
		 * @see confirmEmailAndSignIn
		 */
		public function register($email, $password, $username = null, callable $callback = null)
		{
		}

		/**
		 * Attempts to sign up a user while ensuring that the username is unique
		 * If you want the user's account to be activated by default, pass `null` as the callback
		 * If you want to make the user verify their email address first, pass an anonymous function as the callback
		 * The callback function must have the following signature:
		 * `function ($selector, $token)`
		 * Both pieces of information must be sent to the user, usually embedded in a link
		 * When the user wants to verify their email address as a next step, both pieces will be required again
		 * @param string        $email    the email address to register
		 * @param string        $password the password for the new account
		 * @param string|null   $username (optional) the username that will be displayed
		 * @param callable|null $callback (optional) the function that sends the confirmation email to the user
		 * @return int the ID of the user that has been created (if any)
		 * @throws InvalidEmailException if the email address was invalid
		 * @throws InvalidPasswordException if the password was invalid
		 * @throws UserAlreadyExistsException if a user with the specified email address already exists
		 * @throws DuplicateUsernameException if the specified username wasn't unique
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 * @see confirmEmail
		 * @see confirmEmailAndSignIn
		 */
		public function registerWithUniqueUsername($email, $password, $username = null, callable $callback = null)
		{
		}

		/**
		 * Attempts to sign in a user with their email address and password
		 * @param string        $email            the user's email address
		 * @param string        $password         the user's password
		 * @param int|null      $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
		 * @param callable|null $onBeforeSuccess  (optional) a function that receives the user's ID as its single parameter and is executed before successful authentication; must return `true` to proceed or `false` to cancel
		 * @throws InvalidEmailException if the email address was invalid or could not be found
		 * @throws InvalidPasswordException if the password was invalid
		 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
		 * @throws AttemptCancelledException if the attempt has been cancelled by the supplied callback that is executed before success
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function login($email, $password, $rememberDuration = null, callable $onBeforeSuccess = null)
		{
		}

		/**
		 * Attempts to sign in a user with their username and password
		 * When using this method to authenticate users, you should ensure that usernames are unique
		 * Consistently using {@see registerWithUniqueUsername} instead of {@see register} can be helpful
		 * @param string        $username         the user's username
		 * @param string        $password         the user's password
		 * @param int|null      $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
		 * @param callable|null $onBeforeSuccess  (optional) a function that receives the user's ID as its single parameter and is executed before successful authentication; must return `true` to proceed or `false` to cancel
		 * @throws UnknownUsernameException if the specified username does not exist
		 * @throws AmbiguousUsernameException if the specified username is ambiguous, i.e. there are multiple users with that name
		 * @throws InvalidPasswordException if the password was invalid
		 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
		 * @throws AttemptCancelledException if the attempt has been cancelled by the supplied callback that is executed before success
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function loginWithUsername($username, $password, $rememberDuration = null, callable $onBeforeSuccess = null)
		{
		}

		/**
		 * Attempts to confirm the currently signed-in user's password again
		 * Whenever you want to confirm the user's identity again, e.g. before
		 * the user is allowed to perform some "dangerous" action, you should
		 * use this method to confirm that the user is who they claim to be.
		 * For example, when a user has been remembered by a long-lived cookie
		 * and thus {@see isRemembered} returns `true`, this means that the
		 * user has not entered their password for quite some time anymore.
		 * @param string $password the user's password
		 * @return bool whether the supplied password has been correct
		 * @throws NotLoggedInException if the user is not currently signed in
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function reconfirmPassword($password)
		{
		}

		/**
		 * Logs the user out
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function logOut()
		{
		}

		/**
		 * Logs the user out in all other sessions (except for the current one)
		 * @throws NotLoggedInException if the user is not currently signed in
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function logOutEverywhereElse()
		{
		}

		/**
		 * Logs the user out in all sessions
		 * @throws NotLoggedInException if the user is not currently signed in
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function logOutEverywhere()
		{
		}

		/**
		 * Destroys all session data
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function destroySession()
		{
		}

		/**
		 * Creates a new directive keeping the user logged in ("remember me")
		 * @param int $userId   the user ID to keep signed in
		 * @param int $duration the duration in seconds
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		private function createRememberDirective($userId, $duration)
		{
		}

		protected function deleteRememberDirectiveForUserById($userId, $selector = null)
		{
		}

		/**
		 * Sets or updates the cookie that manages the "remember me" token
		 * @param string|null $selector the selector from the selector/token pair
		 * @param string|null $token    the token from the selector/token pair
		 * @param int         $expires  the UNIX time in seconds which the token should expire at
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		private function setRememberCookie($selector, $token, $expires)
		{
		}

		protected function onLoginSuccessful($userId, $email, $username, $status, $roles, $forceLogout, $remembered)
		{
		}

		/**
		 * Deletes the session cookie on the client
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		private function deleteSessionCookie()
		{
		}

		/**
		 * Confirms an email address (and activates the account) by supplying the correct selector/token pair
		 * The selector/token pair must have been generated previously by registering a new account
		 * @param string $selector the selector from the selector/token pair
		 * @param string $token    the token from the selector/token pair
		 * @return string[] an array with the old email address (if any) at index zero and the new email address (which has just been verified) at index one
		 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
		 * @throws TokenExpiredException if the token has already expired
		 * @throws UserAlreadyExistsException if an attempt has been made to change the email address to a (now) occupied address
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function confirmEmail($selector, $token)
		{
		}

		/**
		 * Confirms an email address and activates the account by supplying the correct selector/token pair
		 * The selector/token pair must have been generated previously by registering a new account
		 * The user will be automatically signed in if this operation is successful
		 * @param string   $selector         the selector from the selector/token pair
		 * @param string   $token            the token from the selector/token pair
		 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
		 * @return string[] an array with the old email address (if any) at index zero and the new email address (which has just been verified) at index one
		 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
		 * @throws TokenExpiredException if the token has already expired
		 * @throws UserAlreadyExistsException if an attempt has been made to change the email address to a (now) occupied address
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function confirmEmailAndSignIn($selector, $token, $rememberDuration = null)
		{
		}

		/**
		 * Changes the currently signed-in user's password while requiring the old password for verification
		 * @param string $oldPassword the old password to verify account ownership
		 * @param string $newPassword the new password that should be set
		 * @throws NotLoggedInException if the user is not currently signed in
		 * @throws InvalidPasswordException if either the old password has been wrong or the desired new one has been invalid
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function changePassword($oldPassword, $newPassword)
		{
		}

		/**
		 * Changes the currently signed-in user's password without requiring the old password for verification
		 * @param string $newPassword the new password that should be set
		 * @throws NotLoggedInException if the user is not currently signed in
		 * @throws InvalidPasswordException if the desired new password has been invalid
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function changePasswordWithoutOldPassword($newPassword)
		{
		}

		/**
		 * Attempts to change the email address of the currently signed-in user (which requires confirmation)
		 * The callback function must have the following signature:
		 * `function ($selector, $token)`
		 * Both pieces of information must be sent to the user, usually embedded in a link
		 * When the user wants to verify their email address as a next step, both pieces will be required again
		 * @param string   $newEmail the desired new email address
		 * @param callable $callback the function that sends the confirmation email to the user
		 * @throws InvalidEmailException if the desired new email address is invalid
		 * @throws UserAlreadyExistsException if a user with the desired new email address already exists
		 * @throws EmailNotVerifiedException if the current (old) email address has not been verified yet
		 * @throws NotLoggedInException if the user is not currently signed in
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 * @see confirmEmail
		 * @see confirmEmailAndSignIn
		 */
		public function changeEmail($newEmail, callable $callback)
		{
		}

		/**
		 * Attempts to re-send an earlier confirmation request for the user with the specified email address
		 * The callback function must have the following signature:
		 * `function ($selector, $token)`
		 * Both pieces of information must be sent to the user, usually embedded in a link
		 * When the user wants to verify their email address as a next step, both pieces will be required again
		 * @param string   $email    the email address of the user to re-send the confirmation request for
		 * @param callable $callback the function that sends the confirmation request to the user
		 * @throws ConfirmationRequestNotFound if no previous request has been found that could be re-sent
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 */
		public function resendConfirmationForEmail($email, callable $callback)
		{
		}

		/**
		 * Attempts to re-send an earlier confirmation request for the user with the specified ID
		 * The callback function must have the following signature:
		 * `function ($selector, $token)`
		 * Both pieces of information must be sent to the user, usually embedded in a link
		 * When the user wants to verify their email address as a next step, both pieces will be required again
		 * @param int      $userId   the ID of the user to re-send the confirmation request for
		 * @param callable $callback the function that sends the confirmation request to the user
		 * @throws ConfirmationRequestNotFound if no previous request has been found that could be re-sent
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 */
		public function resendConfirmationForUserId($userId, callable $callback)
		{
		}

		/**
		 * Attempts to re-send an earlier confirmation request
		 * The callback function must have the following signature:
		 * `function ($selector, $token)`
		 * Both pieces of information must be sent to the user, usually embedded in a link
		 * When the user wants to verify their email address as a next step, both pieces will be required again
		 * You must never pass untrusted input to the parameter that takes the column name
		 * @param string   $columnName  the name of the column to filter by
		 * @param mixed    $columnValue the value to look for in the selected column
		 * @param callable $callback    the function that sends the confirmation request to the user
		 * @throws ConfirmationRequestNotFound if no previous request has been found that could be re-sent
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		private function resendConfirmationForColumnValue($columnName, $columnValue, callable $callback)
		{
		}

		/**
		 * Initiates a password reset request for the user with the specified email address
		 * The callback function must have the following signature:
		 * `function ($selector, $token)`
		 * Both pieces of information must be sent to the user, usually embedded in a link
		 * When the user wants to proceed to the second step of the password reset, both pieces will be required again
		 * @param string   $email               the email address of the user who wants to request the password reset
		 * @param callable $callback            the function that sends the password reset information to the user
		 * @param int|null $requestExpiresAfter (optional) the interval in seconds after which the request should expire
		 * @param int|null $maxOpenRequests     (optional) the maximum number of unexpired and unused requests per user
		 * @throws InvalidEmailException if the email address was invalid or could not be found
		 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
		 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function forgotPassword($email, callable $callback, $requestExpiresAfter = null, $maxOpenRequests = null)
		{
		}

		/**
		 * Authenticates an existing user
		 * @param string        $password         the user's password
		 * @param string|null   $email            (optional) the user's email address
		 * @param string|null   $username         (optional) the user's username
		 * @param int|null      $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
		 * @param callable|null $onBeforeSuccess  (optional) a function that receives the user's ID as its single parameter and is executed before successful authentication; must return `true` to proceed or `false` to cancel
		 * @throws InvalidEmailException if the email address was invalid or could not be found
		 * @throws UnknownUsernameException if an attempt has been made to authenticate with a non-existing username
		 * @throws AmbiguousUsernameException if an attempt has been made to authenticate with an ambiguous username
		 * @throws InvalidPasswordException if the password was invalid
		 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
		 * @throws AttemptCancelledException if the attempt has been cancelled by the supplied callback that is executed before success
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		private function authenticateUserInternal(
			$password,
			$email = null,
			$username = null,
			$rememberDuration = null,
			callable $onBeforeSuccess = null
		) {
		}

		/**
		 * Returns the requested user data for the account with the specified email address (if any)
		 * You must never pass untrusted input to the parameter that takes the column list
		 * @param string $email            the email address to look for
		 * @param array  $requestedColumns the columns to request from the user's record
		 * @return array the user data (if an account was found)
		 * @throws InvalidEmailException if the email address could not be found
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		private function getUserDataByEmailAddress($email, array $requestedColumns)
		{
		}

		/**
		 * Returns the number of open requests for a password reset by the specified user
		 * @param int $userId the ID of the user to check the requests for
		 * @return int the number of open requests for a password reset
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		private function getOpenPasswordResetRequests($userId)
		{
		}

		/**
		 * Creates a new password reset request
		 * The callback function must have the following signature:
		 * `function ($selector, $token)`
		 * Both pieces of information must be sent to the user, usually embedded in a link
		 * When the user wants to proceed to the second step of the password reset, both pieces will be required again
		 * @param int      $userId       the ID of the user who requested the reset
		 * @param int      $expiresAfter the interval in seconds after which the request should expire
		 * @param callable $callback     the function that sends the password reset information to the user
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		private function createPasswordResetRequest($userId, $expiresAfter, callable $callback)
		{
		}

		/**
		 * Resets the password for a particular account by supplying the correct selector/token pair
		 * The selector/token pair must have been generated previously by calling `Auth#forgotPassword(...)`
		 * @param string $selector    the selector from the selector/token pair
		 * @param string $token       the token from the selector/token pair
		 * @param string $newPassword the new password to set for the account
		 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
		 * @throws TokenExpiredException if the token has already expired
		 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
		 * @throws InvalidPasswordException if the new password was invalid
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function resetPassword($selector, $token, $newPassword)
		{
		}

		/**
		 * Check if the supplied selector/token pair can be used to reset a password
		 * The password can be reset using the supplied information if this method does *not* throw any exception
		 * The selector/token pair must have been generated previously by calling `Auth#forgotPassword(...)`
		 * @param string $selector the selector from the selector/token pair
		 * @param string $token    the token from the selector/token pair
		 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
		 * @throws TokenExpiredException if the token has already expired
		 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
		 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function canResetPasswordOrThrow($selector, $token)
		{
		}

		/**
		 * Check if the supplied selector/token pair can be used to reset a password
		 * The selector/token pair must have been generated previously by calling `Auth#forgotPassword(...)`
		 * @param string $selector the selector from the selector/token pair
		 * @param string $token    the token from the selector/token pair
		 * @return bool whether the password can be reset using the supplied information
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function canResetPassword($selector, $token)
		{
		}

		/**
		 * Sets whether password resets should be permitted for the account of the currently signed-in user
		 * @param bool $enabled whether password resets should be enabled for the user's account
		 * @throws NotLoggedInException if the user is not currently signed in
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function setPasswordResetEnabled($enabled)
		{
		}

		/**
		 * Returns whether password resets are permitted for the account of the currently signed-in user
		 * @return bool
		 * @throws NotLoggedInException if the user is not currently signed in
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function isPasswordResetEnabled()
		{
		}

		/**
		 * Returns whether the user is currently logged in by reading from the session
		 * @return boolean whether the user is logged in or not
		 */
		public function isLoggedIn()
		{
		}

		/**
		 * Shorthand/alias for ´isLoggedIn()´
		 * @return boolean
		 */
		public function check()
		{
		}

		/**
		 * Returns the currently signed-in user's ID by reading from the session
		 * @return int the user ID
		 */
		public function getUserId()
		{
		}

		/**
		 * Shorthand/alias for `getUserId()`
		 * @return int
		 */
		public function id()
		{
		}

		/**
		 * Returns the currently signed-in user's email address by reading from the session
		 * @return string the email address
		 */
		public function getEmail()
		{
		}

		/**
		 * Returns the currently signed-in user's display name by reading from the session
		 * @return string the display name
		 */
		public function getUsername()
		{
		}

		/**
		 * Returns the currently signed-in user's status by reading from the session
		 * @return int the status as one of the constants from the {@see Status} class
		 */
		public function getStatus()
		{
		}

		/**
		 * Returns whether the currently signed-in user is in "normal" state
		 * @return bool
		 * @see Status
		 * @see Auth::getStatus
		 */
		public function isNormal()
		{
			return $this->getStatus() === Status::NORMAL;
		}

		/**
		 * Returns whether the currently signed-in user is in "archived" state
		 * @return bool
		 * @see Status
		 * @see Auth::getStatus
		 */
		public function isArchived()
		{
			return $this->getStatus() === Status::ARCHIVED;
		}

		/**
		 * Returns whether the currently signed-in user is in "banned" state
		 * @return bool
		 * @see Status
		 * @see Auth::getStatus
		 */
		public function isBanned()
		{
			return $this->getStatus() === Status::BANNED;
		}

		/**
		 * Returns whether the currently signed-in user is in "locked" state
		 * @return bool
		 * @see Status
		 * @see Auth::getStatus
		 */
		public function isLocked()
		{
			return $this->getStatus() === Status::LOCKED;
		}

		/**
		 * Returns whether the currently signed-in user is in "pending review" state
		 * @return bool
		 * @see Status
		 * @see Auth::getStatus
		 */
		public function isPendingReview()
		{
			return $this->getStatus() === Status::PENDING_REVIEW;
		}

		/**
		 * Returns whether the currently signed-in user is in "suspended" state
		 * @return bool
		 * @see Status
		 * @see Auth::getStatus
		 */
		public function isSuspended()
		{
			return $this->getStatus() === Status::SUSPENDED;
		}

		/**
		 * Returns whether the currently signed-in user has the specified role
		 * @param int $role the role as one of the constants from the {@see Role} class
		 * @return bool
		 * @see Role
		 */
		public function hasRole($role)
		{
		}

		/**
		 * Returns whether the currently signed-in user has *any* of the specified roles
		 * @param int[] ...$roles the roles as constants from the {@see Role} class
		 * @return bool
		 * @see Role
		 */
		public function hasAnyRole(...$roles)
		{
		}

		/**
		 * Returns whether the currently signed-in user has *all* of the specified roles
		 * @param int[] ...$roles the roles as constants from the {@see Role} class
		 * @return bool
		 * @see Role
		 */
		public function hasAllRoles(...$roles)
		{
		}

		/**
		 * Returns an array of the user's roles, mapping the numerical values to their descriptive names
		 * @return array
		 */
		public function getRoles()
		{
		}

		/**
		 * Returns whether the currently signed-in user has been remembered by a long-lived cookie
		 * @return bool whether they have been remembered
		 */
		public function isRemembered()
		{
		}

		/**
		 * Returns the user's current IP address
		 * @return string the IP address (IPv4 or IPv6)
		 */
		public function getIpAddress()
		{
		}

		/**
		 * Performs throttling or rate limiting using the token bucket algorithm (inverse leaky bucket algorithm)
		 * @param array     $criteria   the individual criteria that together describe the resource that is being throttled
		 * @param int       $supply     the number of units to provide per interval (>= 1)
		 * @param int       $interval   the interval (in seconds) for which the supply is provided (>= 5)
		 * @param int|null  $burstiness (optional) the permitted degree of variation or unevenness during peaks (>= 1)
		 * @param bool|null $simulated  (optional) whether to simulate a dry run instead of actually consuming the requested units
		 * @param int|null  $cost       (optional) the number of units to request (>= 1)
		 * @return float the number of units remaining from the supply
		 * @throws TooManyRequestsException if the actual demand has exceeded the designated supply
		 * @throws AuthError if an internal problem occurred (do *not* catch)
		 */
		public function throttle(array $criteria, $supply, $interval, $burstiness = null, $simulated = null, $cost = null)
		{
		}

		/**
		 * Returns the component that can be used for administrative tasks
		 * You must offer access to this interface to authorized users only (restricted via your own access control)
		 * @return Administration
		 */
		public function admin()
		{
			return new Administration($this->db, $this->dbTablePrefix, $this->dbSchema);
		}

		/**
		 * Creates a UUID v4 as per RFC 4122
		 * The UUID contains 128 bits of data (where 122 are random), i.e. 36 characters
		 * @return string the UUID
		 * @author Jack @ Stack Overflow
		 */
		public static function createUuid()
		{
			$data = \openssl_random_pseudo_bytes(16);

			// set the version to 0100
			$data[6] = \chr(\ord($data[6]) & 0x0f | 0x40);
			// set bits 6-7 to 10
			$data[8] = \chr(\ord($data[8]) & 0x3f | 0x80);

			return \vsprintf('%s%s-%s-%s-%s-%s%s%s', \str_split(\bin2hex($data), 4));
		}

		/**
		 * Generates a unique cookie name for the given descriptor based on the supplied seed
		 * @param string      $descriptor a short label describing the purpose of the cookie, e.g. 'session'
		 * @param string|null $seed       (optional) the data to deterministically generate the name from
		 * @return string
		 */
		public static function createCookieName($descriptor, $seed = null)
		{
		}

		/**
		 * Generates a unique cookie name for the 'remember me' feature
		 * @param string|null $sessionName (optional) the session name that the output should be based on
		 * @return string
		 */
		public static function createRememberCookieName($sessionName = null)
		{
		}

		/**
		 * Returns the selector of a potential locally existing remember directive
		 * @return string|null
		 */
		private function getRememberDirectiveSelector()
		{
		}

		/**
		 * Returns the expiry date of a potential locally existing remember directive
		 * @return int|null
		 */
		private function getRememberDirectiveExpiry()
		{
		}
	}
