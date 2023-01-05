#!/usr/bin/env python

import requests
import logging
import re
import urllib.parse

# URL constants
HACKADAY_URL = "https://hackaday.io"
LOGIN_URL = HACKADAY_URL + "/signin"
PROJECT_URL = HACKADAY_URL + "/project"
PROJECT_SAVE_URL = PROJECT_URL + "/save"
PROJECT_DELETE_URL = PROJECT_URL + "/{}/delete"  # Requires string formatting to work
POST_SAVE_URL = HACKADAY_URL + "/post/{}/save"  # Requires string formatting to work     

# REGEX constants
CSRF_RE = "var csrftoken = '(.{36})';"   # Regex search to pull the CSRF cookie - it's found in the JS of the login page & always 36 characters long.

# Request headers
HEADERS = {
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5',
  'Accept-Encoding': 'gzip, deflate, br',
  'Content-Type': 'application/x-www-form-urlencoded',
  'Origin': 'https://hackaday.io',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'same-origin',
  'Sec-Fetch-User': '?1'
}

# Logging
log_level = logging.INFO

# Initialize logger
logger = logging.getLogger(__name__)
logger.setLevel(log_level)

logging.basicConfig(filename="hackaday_client.log", level=log_level)

ch = logging.StreamHandler()
ch.setLevel(log_level)

formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s]: %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


# Definition of some error classes
class InvalidHttpReturnException(Exception):
    'Rasied when Hackaday returns an unexpected HTTP Status code'
    pass

class FailedToExtractCsrfTokenException(Exception):
    'Rasied when there is a failure to extract the CSRF token'
    pass

class InvalidProjectSaveParamsException(Exception):
    'Rasied when there is a bad input into the project save method'
    pass

class InvalidHackadaySessionException(Exception):
    'Raised when there is an invalid requests.Session used'
    pass

class FailedToExtractUserIdException(Exception):
    'Raised when the user\'s ID could not be extracted'
    pass

class FailedToExtractProjectIdException(Exception):
    'Raised when the project\'s ID could not be extracted'
    pass

class ProjectDoesNotExistException(Exception):
    'Raised when a specified project doesn\'t exist'
    pass

class ProjectIsNotOwnedException(Exception):
    'Raised when a user doesn\'t have permissions to edit/delete a project as they don\'t own it'
    pass


class HackadayWeb:
    'Hackaday Web Client'
    def __init__(self, email:str, password:str):
        self.hd_sesh = self.hackadayLogin(email, password)
        # self.checkSessionValid(self.hd_sesh)    # Validate session cookies


    def hackadayLogin(self, email:str, password:str):
        hd_sesh = requests.Session()    # Create a new requests session for the hackaday login.

        get_login = hd_sesh.get(LOGIN_URL, headers=HEADERS)    # Grab the login page to pull the login CSRF token

        self.checkHttpStatusCode(get_login, requests.status_codes.codes.ok, "GET login page") # Check the status code, toss an error if not 200
        
        logger.info("Attempt to pull Hackaday login page returned HTTP status code " + str(requests.status_codes.codes.ok) + ".")
        
        try:
            self.login_csrf = re.search(CSRF_RE, get_login.text).group(1)    # Pull the CSRF token from the JS side of the login page
            logger.info("Login CSRF token seemingly successfully parsed as: \"" + self.login_csrf + "\"")
        except AttributeError as err:
            err_msg = "Failed running REGEX match on login page contents: " + err
            logger.error(err_msg)
            raise FailedToExtractCsrfTokenException(err_msg)

        login_vars = {
            "email": email,
            "password": password,
            "_csrf": self.login_csrf
        }

        post_login = hd_sesh.post(LOGIN_URL, headers=HEADERS, data=login_vars)
        self.checkHttpStatusCode(post_login, requests.status_codes.codes.ok, "POST login information") # Confirm login was successful
        logger.info("Attempt to login to Hackaday returned HTTP status code " + str(requests.status_codes.codes.ok) + ".")

        return hd_sesh


    # Uses the API from the Hackaday.io create/edit project prompt. If save is successful, the project's ID is returned.
    def saveProject(self, name:str, summary:str, description:str="", tags:list=["ongoing project"], id="", links:list=None, files:list=None, images:list=None, projectType:str="project", private:bool=False, updateFeed:bool=True):

        # Sanity check to confirm bare minimum fields are populated
        required_fields = {"_csrf": self.login_csrf, "name": name, "summary": summary}
        self.checkRequiredFields(required_fields=required_fields)
        
        # Format private & update feed statuses to fit the hackaday flow
        updateFeed = "on" if updateFeed else "off"
        private = "on" if private else "off"

        # Populate form data based off of params

        proj_payload = required_fields

        # proj_payload.update({
        #     "description": description,
        #     "id": id,
        #     "private": private,
        #     "updateFeed": updateFeed,
        #     "projectType": projectType,
        #     "tindieProductId": "",
        #     "contributor": ""
        # })

        proj_payload.update({
        "id": id,
        "projectType": projectType,
        "badgeId": "",
        "description": description,
        "contributor": "",
        "updateFeed": updateFeed,
        "tindieProductId": "",
        "private": private
        })

        proj_payload = urllib.parse.urlencode(proj_payload)

        # Handle files, images & tags as they are done weird in Hackaday params

        if not tags or len(tags) <= 0:
            tags = [""]

        tags.append("")
        for i in range(len(tags)):
            proj_payload += "&" + urllib.parse.urlencode({"tag": tags[i]})
            proj_payload += "&" + urllib.parse.urlencode({"tags[" + str(i) + "][id]": tags[i]})
            proj_payload += "&" + urllib.parse.urlencode({"tags[" + str(i) + "][value]": "-1"})
            proj_payload += "&" + urllib.parse.urlencode({"tags[" + str(i) + "][removed]": "false"})

        #########################################
        #   IMAGES & LINKS NOT YET SUPPORTED    #
        #########################################

        # if not files or len(files) <= 0:
        #     files = [""]
        
        # files.append("")
        # for i in range(len(files)):
        #     proj_payload += "&" + urllib.parse.urlencode({"file": files[i]})

        # if not links or len(links) <= 0:
        #     links = [""]

        # links.append("")
        # for i in range(len(links)):
        #     proj_payload += "&" + urllib.parse.urlencode({"links[" + str(i) + "][type]": "-1"})
        #     proj_payload += "&" + urllib.parse.urlencode({"links[" + str(i) + "][id]": ""})
        #     proj_payload += "&" + urllib.parse.urlencode({"links[" + str(i) + "][title]": ""})
        #     proj_payload += "&" + urllib.parse.urlencode({"links[" + str(i) + "][url]": ""})
        
        # if images and len(images) > 0:
        #     for i in range(len(images) - 1):
        #         proj_payload += "&" + urllib.parse.urlencode(files[i])

        logger.debug("Generated \"save project\" string w/ URL encoding: \"" + proj_payload + "\".")
        post_save_proj = self.hd_sesh.post(PROJECT_SAVE_URL, headers=HEADERS, data=proj_payload)
        self.checkHttpStatusCode(post_save_proj, requests.status_codes.codes.ok, "POST project save") # Confirm login was successful
        logger.info("Attempt to save Hackaday project returned HTTP status code " + str(requests.status_codes.codes.ok) + ".")
        logger.debug(post_save_proj.text)
        
        # Return the project ID by parsing the redirect URL passed to the request.
        try:
            proj_id_out = re.search("https:\/\/hackaday.io\/project\/(.{6})-", post_save_proj.url).group(1)
            return proj_id_out
        except AttributeError as err:
            raise FailedToExtractProjectIdException("Created project ID couldn't be extracted (was it actually created?): " + str(err))


    def deleteProject(self, proj_id:str):

        proj_owner = self.checkProjectExists(proj_id=proj_id)

        if not proj_owner:  # Project doesn't exist
            raise ProjectDoesNotExistException("Failed to find project to delete!")

        if proj_owner != self.hd_sesh.cookies["haveAccountCookie"]:
            raise ProjectIsNotOwnedException("Cannot delete this project as the logged in user doesn't own it!")

        delete_proj_url = PROJECT_DELETE_URL.format(proj_id)
        delete_payload = {"_csrf": self.login_csrf}

        logger.debug("Attempting delete using URL: " + delete_proj_url)

        delete_proj = self.hd_sesh.post(delete_proj_url, headers=HEADERS, data=delete_payload) # To delete a project, the sessions csrf needs to be posted to the URL.

        self.checkHttpStatusCode(delete_proj, requests.status_codes.codes.ok, "GET delete project") # Confirm login was successful
        logger.info("Attempt to delete Hackaday project returned HTTP status code " + str(requests.status_codes.codes.ok) + ".")
        logger.debug(delete_proj.text)


    # Creates a new project by leveraging the saveProject method. Returns the project ID that was created. 
    def createProject(self, name:str, summary:str, description:str=None, tags:list=None, links:list=None, files:list=None, images:list=None, projectType:str=None, private:bool=None, updateFeed:bool=None):

        # A list of project args, the only required args are name, summary, and description. The rest will be handed by the saveProject() method.
        proj_args= {
            "name": name, 
            "summary": summary,
            "description": description,
            "tags": tags,
            "links": links,
            "files": files,
            "images": images,
            "projectType": projectType,
            "private": private,
            "updateFeed": updateFeed
        }

        args_to_remove = []

        for arg in proj_args.keys():    # Check if any of the input values == None, if so don't pass them to saveProject.
            if (not proj_args[arg]):
                args_to_remove.append(arg)
        
        for arg in args_to_remove:
            proj_args.pop(arg)

        project_id = self.saveProject(**proj_args)   # Run the saveProject method with specified arguments
        return project_id


    # Used to save a projects details & logs.
    def savePost(self, body:str, projectId:str, postId:str, category:str, type:str, projectName:str, title:str=None):
        save_details_url = POST_SAVE_URL.format(projectId)

        required_fields = {"_csrf": self.login_csrf, "body": body, "projectId": projectId}
        if category in ["log"]: # Title is only in log saves
            required_fields.update({"title": title})
        
        self.checkRequiredFields(required_fields=required_fields)

        post_payload = required_fields

        post_payload.update({
            "body": body,
            "projectId": projectId,
            "postId": postId,
            "category": category,
            "type": type,
            "projectName": projectName
        })

        post_save = self.hd_sesh.post(save_details_url, headers=HEADERS, data=post_payload) # To delete a project, the sessions csrf needs to be posted to the URL.
        
        self.checkHttpStatusCode(post_save, requests.status_codes.codes.ok, "POST save post") # Confirm login was successful
        logger.info("Attempt to save Hackaday post " + category + " returned HTTP status code " + str(requests.status_codes.codes.ok) + ".")
        logger.debug(post_save.text)


    def addDetails(self, body:str, projectId:str, postId:str="", type:str="project", projectName:str=""):
        # Method just passes all args to savePost, adding category as details

        # Confirm the user owns the specified project
        proj_owner = self.checkProjectExists(proj_id=projectId)
        if proj_owner != self.hd_sesh.cookies["haveAccountCookie"]:
            raise ProjectIsNotOwnedException("Cannot log work on this project as the logged in user doesn't own it!")

        category = "details"

        details_args = {
            "category": category,
            "body": body, 
            "projectId": projectId, 
            "postId": postId, 
            "type": type, 
            "projectName": projectName
        }

        self.savePost(**details_args)

    def addLogEntry(self, body:str, title:str, projectId:str, postId:str="", type:str="project", projectName:str=""):
        # Method just passes all args to savePost, adding category as log
        
        # Confirm the user owns the specified project
        proj_owner = self.checkProjectExists(proj_id=projectId)
        if proj_owner != self.hd_sesh.cookies["haveAccountCookie"]:
            raise ProjectIsNotOwnedException("Cannot log work on this project as the logged in user doesn't own it!")

        category = "log"

        details_args = {
            "category": category,
            "title": title,
            "body": body, 
            "projectId": projectId, 
            "postId": postId, 
            "type": type, 
            "projectName": projectName
        }

        self.savePost(**details_args)        


    def checkProjectExists(self, proj_id:str):
        get_proj_url = PROJECT_URL + "/" + proj_id
        get_proj = self.hd_sesh.get(get_proj_url, headers=HEADERS)

        # Check if a valid 200 code was returned, if not return false
        try:
            self.checkHttpStatusCode(get_proj, requests.status_codes.codes.ok, "GET project")
        except InvalidHttpReturnException:
            return False 

        logger.info("Attempt to get Hackaday project returned HTTP status code " + str(requests.status_codes.codes.ok) + ".")

        # Attempt to pull the user ID from the project page and return it to indicate an existing project.
        try:
            project_user_id = re.search('<span class="identity-card" data-id="(.{7})">', get_proj.text).group(1)
            return project_user_id

        except AttributeError as err:
            raise FailedToExtractUserIdException("Failed to extract the user ID from the specified project page: " + str(err))


    # Compare HTTP codes to confirm the intended one was recieved.
    def checkHttpStatusCode(self, request, intended_status, attempted_action):
        returned_status = request.status_code
        if returned_status != intended_status:
                err_msg = "Attempt to " + attempted_action + " returned code \"" + str(returned_status) + "\" when the expected return was \"" + str(intended_status) + "\""
                logger.error(err_msg)
                logger.debug(request.text)
                raise InvalidHttpReturnException(err_msg)


    # Method to confirm the session has all of the required cookies to execute operations
    def checkSessionValid(self, hd_sesh:requests.Session):
        req_cookies = ["_csrf", "haveAccountCookie"] # removed: "hackaday.io.sid"
        sesh_cookies = hd_sesh.cookies.keys()
        for cookie in req_cookies:
            if cookie in sesh_cookies:
                req_cookies.remove(cookie)

        if len(req_cookies) != 0:
            raise InvalidHackadaySessionException("The used session was lacking the following cookies: " + str(req_cookies))


    # Method to confirm all keys in a dict have a value that isn't None or ""
    def checkRequiredFields(self, required_fields:dict):
        for field in required_fields.keys():
            if required_fields.get(field) == None or required_fields.get(field) == "":
                raise InvalidProjectSaveParamsException("Invalid parameters provided: \"" + field + "\" needs to be populated!") 


if __name__ == "__main__":
    import argparse

    # Initialize parser
    parser = argparse.ArgumentParser()

    # Add email & password arguments
    parser.add_argument("-e", "--email", help="Specify Hackaday email")
    parser.add_argument("-p", "--password", help="Specify Hackaday password")

    args = parser.parse_args()


    hackadaySession = HackadayWeb(email=args.email, password=args.password)

    proj_id = hackadaySession.createProject(
                    name="Test Project", 
                    summary="This is a test from a script written by a lamemakes.", 
                    description="Cool stuff, I promise.", 
                    private=True
                )

    hackadaySession.addDetails(body="<p><strong>Details Test</strong><br>This is a details test!</p>", projectId=proj_id)
    hackadaySession.addLogEntry(title="Listened to Quelle Chris", body="<p>Real big boy pants</p>", projectId=proj_id)
