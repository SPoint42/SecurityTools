import os
import sys
import argparse
import requests
import gitlab


DEBUG = False

class DevSecOPSGitlab(object):
    """
    A class to manipulate a gitlab connection

    Attributes
    ----------

    id : int
        gitlabID
    gitlab_url : str
        URL of the gitlab server (default to gitlab.com)
    gitlab_token : str
        Token to connect to Gitlab API
    gitlab_user : str
        user if neeed
    projectID : int
        Id of the project if sucessufl retreive
    group : object
        gitlab group if sucessuf Retreive
    gitlab_connection: object
        gitlab if connection if sucessfull



    """

    def __init__(self):

        self.id = None
        self.gitlab_url = 'https://gitlab.com'
        self.gitlab_connection = None
        self.gitlab_token = None
        self.gitlab_user = 'github@gioria.org'
        self.projectID = None
        self.group = None

    def connection(self):
        """
        Connect to the gitlab.com url specified in  the class element
        :return:
        """
        # private token or personal token authentication
        try:
            self.gitlab_connection = gitlab.Gitlab(self.gitlab_url,
                                                   private_token=self.gitlab_token)
            self.gitlab_connection.auth()
            if DEBUG:
                print ("Successful auth in GitLab ")
            return True

        except Exception as e:
            raise (e)
            return False

    def getGitlabProjectIDbyRepo (self, projectRepo):
        """
        Connect to the gitlab.com url specified in  the class element

        :projectRepo: projectRepo URL

        :return: the projectID
        """

        if DEBUG:
            print ("Repo " + projectRepo)
        self.projectID = self.gitlab_connection.projects.get(projectRepo)

        return self.projectID

    def getGitlabGroupID (self, groupName):
        self.group  = self.gitlab_connection.groups.get(groupName)
        self.groupID = self.group.id

        return self.groupID


def publicRepo(json=False):
    gl = DevSecOPSGitlab.DevSecOPSGitlab()

    gl.gitlab_token = os.environ['GITLAB_TOKEN']
    gl.gitlab_url = 'https://gitlab.com'
    try:
        gl.connection()
        gl.groupID = gl.getGitlabGroupID('starwars')
        gl.group = gl.gitlab_connection.groups.get(gl.groupID)
        members = gl.group.members.list(get_all=True)

        tab = list ()

        for member in members:
            user = gl.gitlab_connection.users.get(member.id)
            projects = user.projects.list()
            for project in projects:
                tab.append (
                    {
                        'repo': project.web_url,
                        'user' : user.username
                    }
                )
                if json is False:
                    print (user.username + '\t -> '+ project.web_url)


    except Exception as e:
        raise(e)

    return tab


def main(argv):
    try:
        parser = argparse.ArgumentParser(description='Some gitlab tools ', allow_abbrev=True)
        parser.add_argument('--publicRepo', type=bool, default=False, help='Listing of public repos', required=False)
        parser.add_argument('--json', type=bool, default=False, help='Export in JSON format', required=False)
        parser.add_argument('--url2sent', type=str, help='Export to an URL', required=False)
        parser.add_argument('--print', type=bool, default=False, help='Print on Screen', required=False)
        parser.add_argument('--mock', type=bool, default=False, help='Mock data', required=False)

        args = parser.parse_args()
    except:
        sys.exit(1)


    if args.publicRepo is True:
        print ('Analyse Public repo')
        tab = list()
        if args.mock  :
            tab = (
                {'repo': 'https://gitlab.com/Episode4/Anakin', 'user': 'Anakin'},
                {'repo': 'https://gitlab.com/Episode1/Jedi', 'user': 'Luke'},
            )
        else:
            tab = publicRepo(json=args.json)

        headers = list()

        if args.print :
            print (tab)
        if args.json:
            headers = {'Content-type': 'application/json'}

        if args.url2sent:
            r = requests.post(url = args.url2sent, headers=headers, json = tab)
            print (r.text)



if __name__ == '__main__':
    main(sys.argv[1:])
