# JiraCloudTortoiseGit
Jira Cloud TortoiseGit Issue Tracker Integration

Welcome,

Forked from: https://github.com/csharptest/JiraSVN

Made changes to allow communication between TortoiseGit and Jira Cloud 

The connection with Jira Cloud is made using basic authentication, afaik TortoiseGit does not provide any Oauth interface. 

Username is the Jira username, usually the email address. 

Password is the user token (https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/) 

This plugin uses the Jira Cloud Platform REST API v.2. 

The workflow transitions and worklog tracking methods were still using the SOAP interface, I replaced them with the corresponding REST API methods (https://developer.atlassian.com/server/jira/platform/jira-soap-to-rest-migration-guide/)

Tested with TortoiseGit v.2.13.0.1 and Jira Cloud, using Atlassian .Net SDK (https://bitbucket.org/farmas/atlassian.net-sdk) from Federico Silva Armas

Upped the .NET version from .NET 4.0 TO .NET 4.6

Version 4.0.0.0

This is the first project I upload to Github, forgive me If I miss something or made mistakes, in case please bring them to my attention and I will do my best to make the appropriate changes.

Install file created using Wix Toolset v.3.11

Install msi: https://github.com/lcomastri/JiraCloudTortoiseGit/blob/main/bin/Release/JiraTortoiseGitPlugin-x64.msi









