module seahorse.seahorse;

mixin template Seahorse(string file) {

	import std.string : toLower;

	import seahorse.util;

	import scorpion.config : parseProperties;
	import scorpion;

	private enum config = prop!file;

	// ENTITIES
	
	private enum hashMethod = config.get("seahorse.password.hash", "sha256");
	
	static if(hashMethod == "sha1") {
		import std.digest.sha : sha1Of;
		private enum passwordLength = 20;
		private ubyte[] hash(string input){ return sha1Of(input).dup; }
	} else static if(hashMethod == "sha256") {
		import std.digest.sha : sha256Of;
		private enum passwordLength = 32;
		private ubyte[] hash(string input){ return sha256Of(input).dup; }
	} else {
		static assert(0, "Hashing method " ~ hashMethod ~ " is not supported");
	}
	
	@Entity(config.get("seahorse.table.user.name", "seahorse_user"))
	class User {
		
		@PrimaryKey
		@AutoIncrement
		Integer userId;
		
		@Unique
		@NotNull
		@Length(config.get("seahorse.table.user.username.length.max", 32))
		String username;

		@Unique
		@NotNull
		@Length(config.get("seahorse.table.user.username.length.max", 32))
		String usernameLowercase;
		
		@NotNull
		@Length(passwordLength)
		Binary password;

		@Length(64)
		String email;
		
		static if(config.get("seahorse.table.user.names", false)) {
			
			static if(config.get("seahorse.table.user.names.required", false)) alias NamesNotNull = NotNull;
			else enum NamesNotNull;
			
			@NamesNotNull
			@Length(config.get("seahorse.table.user.first-name.length.max", 64))
			String firstName;
			
			@NamesNotNull
			@Length(config.get("seahorse.table.user.last-name.length.max", 64))
			String lastName;
			
		}
		
	}

	@Entity(config.get("seahorse.table.role.name", "seahorse_role"))
	class Role {

		@PrimaryKey
		@AutoIncrement
		Integer roleId;

		@NotNull
		@Length(64)
		String name;

	}

	@Entity(config.get("seahorse.table.user-role.name", "seahorse_user_role"))
	class UserRole {

		@PrimaryKey
		Integer userId;

		@PrimaryKey
		Integer roleId;

	}

	// SERVICES
	
	@Component
	interface UserRepository : Repository!User {

		@Select
		@Where("usernameLowercase=$0")
		User selectByUsername(string username);

		@Insert
		void insert(User user);
		
	}

	@Component
	interface RoleRepository : Repository!Role {

		@Select
		@Where("roleId=$0")
		Role selectByRoleId(uint roleId);

	}

	@Component
	interface UserRoleRepository : Repository!UserRole {

		@Select
		@Where("userId=$0")
		UserRole[] selectByUserId(uint userId);

	}

	// CONTROLLERS

	@Controller("assets")
	class SeahorseAssetsController {
		
		private Resource logo;
		
		this() {
			logo = new CachedResource("image/svg+xml", import("seahorse.logo.svg"));
		}
		
		@Get("seahorse.svg")
		getLogo(Request request, Response response) {
			logo.apply(request, response);
		}
		
	}

	private class SeahorseController {

		@Init
		UserRepository userRepository;
		
		@Init
		RoleRepository roleRepository;
		
		@Init
		UserRoleRepository userRoleRepository;

	}
	
	@Controller(config.get("seahorse.auth.path", "auth"))
	class SeahorseAuthController : SeahorseController {

		@Value("scorpion.index")
		string index = "/";
		
		@Get("login")
		getLogin(Session session, View view) {
			view.render!("seahorse.login.dt", session)();
		}
		
		@Post("login")
		postLogin(Session session, Response response, @Body Login info, Validation validation) {
			if(validation.valid) {
				auto user = userRepository.selectByUsername(info.username.toLower);
				if(user is null) {
					validation.errors ~= Validation.Error("username", "not-found");
				} else if(user.password != hash(info.password)) {
					validation.errors ~= Validation.Error("password", "wrong");
				} else {
					string[] roles;
					foreach(role ; userRoleRepository.selectByUserId(user.userId)) {
						roles ~= roleRepository.selectByRoleId(role.roleId).name;
					}
					session.login(response, new UsernamePasswordAuthentication(user, roles));
				}
			}
		}
		
		@Get("register")
		getRegister(Session session, View view) {
			view.render!("seahorse.register.dt", session)();
		}
		
		@Post("register")
		postRegister(Session session, Response response, @Body Register info, Validation validation) {
			if(session.loggedIn) {
				validation.errors ~= Validation.Error("*", "logged-in");
			} else if(validation.valid) {
				if(userRepository.selectByUsername(info.username.toLower) is null) {
					User user = new User();
					user.username = info.username;
					user.usernameLowercase = info.username.toLower;
					user.password = hash(info.password);
					user.email = info.email.toLower;
					static if(config.get("seahorse.table.user.names", false)) {
						if(info.firstName.length) user.firstName = info.firstName;
						if(info.lastName.length) user.lastName = info.lastName;
					}
					userRepository.insert(user);
					session.login(response, new UsernamePasswordAuthentication(user, []));
				} else {
					validation.errors ~= Validation.Error("username", "already-used");
				}
			}
		}

		@Get("logout")
		getLogout(Session session, Response response) {
			if(session.loggedIn) session.logout();
			response.redirect(StatusCodes.temporaryRedirect, "/" ~ config.get("seahorse.auth.path", "auth") ~ "/login");
		}

		private class UsernamePasswordAuthentication : Authentication {

			private User _user;
			private string[] _roles;

			this(User user, string[] roles) {
				_user = user;
				_roles = roles;
			}

			@property User user() {
				return _user;
			}

			override uint userId() {
				return user.userId;
			}

			override string username() {
				return user.username;
			}

			override string[] roles() {
				return _roles;
			}

		}
		
		private struct Login {
			
			@NotEmpty("empty")
			string username;
			
			@NotEmpty("empty")
			string password;
			
		}
		
		private struct Register {
			
			static if(config.get("seahorse.table.user.names.required", false)) enum NamesOptional;
			else alias NamesOptional = Optional;

			@Min(config.get("seahorse.table.user.username.length.min", 3), "too-short")
			@Max(config.get("seahorse.table.user.username.length.max", 32), "too-long")
			@Regex("[" ~ config.get("seahorse.table.user.username.characters", "a-zA-Z0-9_") ~ "]+", "invalid-characters")
			string username;
			
			@NotEmpty("empty")
			string password;

			@Email("invalid")
			string email;

			static if(config.get("seahorse.table.user.names", false)) {
				
				@NamesOptional
				@Min(config.get("seahorse.table.user.first-name.length.min", 1), "too-short")
				@Max(config.get("seahorse.table.user.first-name.length.max", 64), "too-long")
				string firstName;
				
				@NamesOptional
				@Min(config.get("seahorse.table.user.last-name.length.min", 1), "too-short")
				@Max(config.get("seahorse.table.user.last-name.length.max", 64), "too-long")
				string lastName;

			}
			
		}
		
	}
	
	@Controller(config.get("seahorse.account.path", "account"))
	class SeahorseAccountController : SeahorseController {

	}

}
