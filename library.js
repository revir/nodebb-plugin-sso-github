(function(module) {
	"use strict";

	var User = module.parent.require('./user'),
		db = module.parent.require('./database'),
		meta = module.parent.require('./meta'),
		nconf = module.parent.require('nconf'),
		async = module.parent.require('async'),
		passport = module.parent.require('passport'),
		GithubStrategy = require('passport-github2').Strategy;

	var winston = require('winston');

	var authenticationController = module.parent.require('./controllers/authentication');

	var constants = Object.freeze({
		'name': "GitHub",
		'admin': {
			'icon': 'fa-github',
			'route': '/plugins/sso-github'
		}
	});

	var GitHub = {};

	GitHub.getStrategy = function(strategies, callback) {
		meta.settings.get('sso-github', function(err, settings) {
			if (!err && settings.id && settings.secret) {
				passport.use(new GithubStrategy({
					clientID: settings.id,
					clientSecret: settings.secret,
					callbackURL: nconf.get('url') + '/auth/github/callback',
					passReqToCallback: true,
					scope: [ 'user:email' ] // fetches non-public emails as well
				}, function(req, token, tokenSecret, profile, done) {
					if (req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && req.user.uid > 0) {
						// Save GitHub -specific information to the user
						User.setUserField(req.user.uid, 'githubid', profile.id);
						db.setObjectField('githubid:uid', profile.id, req.user.uid);
						return done(null, req.user);
					}

					var email = Array.isArray(profile.emails) && profile.emails.length ? profile.emails[0].value : '';
					var pictureUrl = Array.isArray(profile.photos) && profile.photos.length ? profile.photos[0].value : '';
					GitHub.login(profile.id, profile.username, email, pictureUrl, function(err, user) {
						if (err) {
							return done(err);
						}

						authenticationController.onSuccessfulLogin(req, user.uid);
						done(null, user);
					});
				}));

				strategies.push({
					name: 'github',
					url: '/auth/github',
					callbackURL: '/auth/github/callback',
					icon: constants.admin.icon,
					scope: 'user:email'
				});
			}

			callback(null, strategies);
		});
	};

	GitHub.getAssociation = function(data, callback) {
		User.getUserField(data.uid, 'githubid', function(err, githubid) {
			if (err) {
				return callback(err, data);
			}

			if (githubid) {
				data.associations.push({
					associated: true,
					name: constants.name,
					icon: constants.admin.icon
				});
			} else {
				data.associations.push({
					associated: false,
					url: nconf.get('url') + '/auth/github',
					name: constants.name,
					icon: constants.admin.icon
				});
			}

			callback(null, data);
		})
	};

	GitHub.login = function(githubID, username, email, pictureUrl, callback) {
		if (!email) {
			email = username + '@users.noreply.github.com';
		}

		GitHub.getUidByGitHubID(githubID, function(err, uid) {
			if (err) {
				return callback(err);
			}

			if (uid) {
				// Existing User
				callback(null, {
					uid: uid
				});
			} else {
				// New User
				var success = function(uid) {
					User.setUserField(uid, 'githubid', githubID);
					db.setObjectField('githubid:uid', githubID, uid);

					// trust the email.
					async.series([
					  async.apply(User.setUserField, uid, 'email:confirmed', 1),
					  async.apply(db.delete, 'uid:' + uid + ':confirm:email:sent'),
					  async.apply(db.sortedSetRemove, 'users:notvalidated', uid),
					  function (next) {
					    // Save their photo, if present
					    if (pictureUrl) {
					      User.setUserField(uid, 'uploadedpicture', pictureUrl);
					      User.setUserField(uid, 'picture', pictureUrl);
					    }
					    next();
					  }
					], function (err) {
					  callback(err, {
					    uid: uid
					  });             
					});

				};

				User.getUidByEmail(email, function(err, uid) {
					if (!uid) {
						User.create({username: username, email: email}, function(err, uid) {
							if (err !== null) {
								callback(err);
							} else {
								success(uid);
							}
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	GitHub.getUidByGitHubID = function(githubID, callback) {
		db.getObjectField('githubid:uid', githubID, function(err, uid) {
			if (err) {
				callback(err);
			} else {
				callback(null, uid);
			}
		});
	};

	GitHub.addMenuItem = function(custom_header, callback) {
		custom_header.authentication.push({
			"route": constants.admin.route,
			"icon": constants.admin.icon,
			"name": constants.name
		});

		callback(null, custom_header);
	};

	GitHub.init = function(data, callback) {
		function renderAdmin(req, res) {
			res.render('admin/plugins/sso-github', {
				callbackURL: nconf.get('url') + '/auth/github/callback'
			});
		}

		data.router.get('/admin/plugins/sso-github', data.middleware.admin.buildHeader, renderAdmin);
		data.router.get('/api/admin/plugins/sso-github', renderAdmin);

		callback();
	};

	GitHub.deleteUserData = function(data, callback) {
		var uid = data.uid;

		async.waterfall([
			async.apply(User.getUserField, uid, 'githubid'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField('githubid:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-github] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err);
				return callback(err);
			}
			callback(null, uid);
		});
	};

	module.exports = GitHub;
}(module));
