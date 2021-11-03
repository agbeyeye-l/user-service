# User-Service
User service provides features such as user registration and profile updates, authentication, and authorization.

### Tech Stacks

- Python
- Django
- Django Restframework (DRF)
- PostgreSQL
- JWT token
- Docker
- Redis 
- Djoser

## Getting Started

- Create a virtual environment to run locally

```bash
   pip install virtualenv
```

```bash
   virtualenv name_of_virtual_env
```

- Activate virtualenv
Windows OS

```bash
    name_of_virtual_env/Scripts/activate
```

- Activate virtualenv
Linux OS

```bash
   source name_of_virtual_env/bin/activate
```


## Running on Docker
- stop any running containers and remove containers, networks, volumes, and images created by up .
```bash
    docker-compose down
```

- build images in the docker-compose.yml file
```bash
    docker-compose build
```

- start or restart all the services defined in a docker-compose.yml file
```bash
    docker-compose up
```

- While docker-compose up is running, lists all running containers in docker engine
```bash
    docker ps
```

- copy container_id of the web app from the above command and use it for the command below:
```bash
 docker exec -it container_id sh
```

- Eventually, you can create a superuser
```bash
     python manage.py createsuperuser
```

- Enter desired email address and password.

```bash
Email address: admin@example.com
Password: **********
Password (again): **********
Superuser created successfully.
```

## <a name='contributing'></a> Contributing

The main purpose of this repository is to continue evolving the User service of SITSC, making it faster and easier to use. Development of user_sitsc will happen in the open on GitHub, and we welcome contributions on bugfixes and improvements.

### Style Guide

#### Python/Django Coding conventions
Keep it SHORT and CLEAR.

Lowercase writing (Uppercase only for constants, everything else is lowercase!)

Use underscore (“_”) to separate the naming (folder naming, variables, methods, etc.)


#### Variable Naming
 
Use underscore (“_”) to make separation inside the name

list_of_users = ...

#### Method Naming
 

Describe what the method does.

get_the_active_users(): pass


#### Bugs

We are using GitHub Issues for our public bugs. We keep a close eye on this and try to make it clear when we have an internal fix in progress. Before filing a new task, try to make sure your problem doesn’t already exist.

#### Proposing a Change

If you intend to change the service, or make any non-trivial changes to the implementation, we recommend filing an issue. This lets us reach an agreement on your proposal before you put significant effort into it.

If you’re only fixing a bug, it’s fine to submit a pull request right away but we still recommend to file an issue detailing what you’re fixing. This is helpful in case we don’t accept that specific fix but want to keep track of the issue.

#### Sending a Pull Request

The engineering team is monitoring for pull requests. We will review your pull request and either merge it, request changes to it, or close it with an explanation. We’ll do our best to provide updates and feedback throughout the process.


#### Contribution Prerequisites

- You have Python and Docker installed, we recommend Python 3.
- You are familiar with Git


