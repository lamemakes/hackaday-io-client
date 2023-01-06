# Hackaday.io Client API
An **unofficial** Hackaday.io client implementation of the Hackaday.io web APIs 

## Why?
This API allows for a user to:
- create & edit Hackaday.io projects
- delete Hackaday.io projects
- add Hackaday.io project details
- add Hackaday.io project logs

This was created as the existing Hackaday.io API doesn't allow for creation/editing of projects. For my own website, I wanted for certain projects to be somewhat sync'd to Hackaday, i.e. when I push a project to my website it automatically translates to the Hackaday.io site.

## Installation
If deemed neccesary, this could be made in a PyPi project in the future.

For now, to install just pull the repo & import HackadayWeb.py into your project.

## Usage
This is assuming usage is as a Python 3 API.

### Setup
First, you need to initialize a new HackadayWeb object using your Hackaday.io username and password:

```hackadayTest = HackadayWeb(email="youremail@yeet.com", password="yourBadPassword!")```

### To create a project:
Utilize the ```createProject()``` method in order to create a project, like such:

```hackadayTest.createProject(name="My Sick New Project", summary="This is my sweet project created by the lamemakes UNOFFICIAL Hackaday.io API!", description="Shoutsout to Hackaday for being a cool platform", tags=["on going", "software"], projectType="project", private=True```

### To add details/logs
Utilize the ```addDetails()``` or ```addLogEntry()``` method in order to add details or log entries to your projects, like:

Details:
```hackadayTest.addDetails(body="<p>This project is really cool, I mean like <strong>really</strong> cool</p>", projectId:"<proj_id returned from createProject()>")```

Logs:
```hackadayTest.addLogEntry(title="Today I worked hard!", body="<p>Today I worked hard, I mean like <strong>really</strong> hard</p>", projectId:"<proj_id returned from createProject()>")```

You can see besides the ```title``` argument on the ```addLogEntry()```, they're identical.

### To delete a project
Utilize the ```deleteProject()``` method in order to delete a specified project, as seen here:
```hackadayTest.deleteProject(proj_id="<ID of a project to delete>")```


## Moving forward
- More in-depth docs to come
- Support for adding files, images, and links to projects
- Support for editing existing projects
