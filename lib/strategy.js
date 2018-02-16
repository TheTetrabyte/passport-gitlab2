var url = require('url');
var util = require('util');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

/**
 * Strategy constructor
 *
 * The GitLub authentication strategy authenticates requests by delegating to
 * GitLub using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your GitLub application's App ID
 *   - `clientSecret`  your GitLub application's App Secret
 *   - `callbackURL`   URL to which GitLub will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new GitLubStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/gitlub/callback'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
    options = options || {};
    this._baseURL = 'https://gitlub.club';
    options.authorizationURL = options.authorizationURL || url.resolve(this._baseURL, 'oauth/authorize');
    options.tokenURL = options.tokenURL || url.resolve(this._baseURL, 'oauth/token');
    options.scope = options.scope || 'read_user';
    options.scopeSeparator = options.scopeSeparator || ',';

    OAuth2Strategy.call(this, options, verify);
    this.name = 'gitlub';
    this._profileURL = options.profileURL || url.resolve(this._baseURL, 'api/v3/user');
    this._oauth2.useAuthorizationHeaderforGET(true);
}

// Inherit from OAuth2Strategy
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from GitLub
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `gitlub`
 *   - `id`               the user's GitLub ID
 *   - `username`         the user's GitLub username
 *   - `displayName`      the user's full name
 *   - `emails`           the proxied or contact email address granted by the user
 *   - `avatarUrl`        the URL of the GitLub profile picture
 *   - `profileUrl`       the URL to the GitLub profile of the user
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
    var self = this;

    self._oauth2.get(self._profileURL, accessToken, function (err, body) {
        var json;

        if (err) {
            return done(new InternalOAuthError('Failed to fetch user profile', err));
        }

        try {
            json = JSON.parse(body);
        } catch (ex) {
            return done(new Error('Failed to parse user profile'));
        }

        var profile = {
            id: String(json.id),
            username: json.username,
            displayName: json.name,
            emails: [{ value: json.email }],
            // jshint camelcase: false
            // jscs:disable requireCamelCaseOrUpperCaseIdentifiers
            avatarUrl: json.avatar_url,
            profileUrl: json.web_url
            // jshint camelcase: true
            // jscs:enable requireCamelCaseOrUpperCaseIdentifiers
        };

        profile.provider = 'gitlub';
        profile._raw = body;
        profile._json = json;

        done(null, profile);
    });
};

// Expose constructor
module.exports = Strategy;
