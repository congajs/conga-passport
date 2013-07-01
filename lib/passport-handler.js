/*
 * This file is part of the conga-passport module.
 *
 * (c) Marc Roulias <marc@lampjunkie.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// third-party modules
var passport = require('passport');

/**
 * The PassportHandler configures and adds the Passport middleware
 * during the kernel boot process.
 * 
 * @author  Marc Roulias <marc@lampjunkie.com>
 */
var PassportHandler = function(){};

PassportHandler.prototype = {

	/**
	 * 
	 * @param {Object} event
	 * @param {Function} next
	 */
	onServerBoot: function(event, next){

		var container = event.container;

		container.set('passport', passport);

		this.registerAdapters(container, function(){
			next();
		});
	},

	/**
	 * Register any defined strategies
	 * 
	 * @param  {Container}  container
	 * @param  {Function}   next
	 * @return {void}
	 */
	registerAdapters: function(container, next){

		var tags = container.getTagsByName('passport.strategy');

		// skip if no strategies have been defined
		if (!tags){
			next();
			return;
		}

		var calls = [];

		for (var i in tags){

			var tag = tags[i];

			(function(tag){
				calls.push(
					function(callback){
						var service = container.get(tag.getServiceId());
						var method = 'register';

						// run the adapter
						service[method].call(service, passport, callback);
					}
				);
			}(tag));
		}

		// run the events!
		container.get('async').series(calls, function(err, results){
			next();
		});
	},

	/**
	 * Add the Passport middleware
	 * 
	 * @param  {Container} container
	 * @param  {Object}    app
	 * @param  {Function}  next
	 * @return {void}
	 */
	onAddMiddleware: function(container, app, next){

		container.get('logger').debug('configuring passport.socketio');

		app.use(passport.initialize());
		app.use(passport.session());

		// try to get socket.io
		var io = container.get('io');

		// configure passport for socket.io
		if (io){

			var passportSocketIo = require("passport.socketio")

			io.configure(function (){

				io.set("authorization", 
					passportSocketIo.authorize({

						cookieParser: container.get('express').cookieParser,

						// the cookie where express (or connect) stores its session id.
						key:    container.get('config').get('framework').session.key,

						// the session secret to parse the cookie
						secret: container.get('config').get('framework').session.secret, 

						// the session store that express uses
						store:   container.get('session.store'),
						fail: function(data, accept) {
							//console.log("failed");
							//console.log(data);// *optional* callbacks on success or fail
							//accept(null, false);             // second param takes boolean on whether or not to allow handshake
							accept(null, true);
						},
						success: function(data, accept) {
							//console.log("success socket.io auth");
							//console.log(data);
							accept(null, true);
						}
					})
				)
			});			
		}

		next();
	}
};

module.exports = PassportHandler;