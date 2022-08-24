#region Copyright 2010 by Roger Knapp, Licensed under the Apache License, Version 2.0
/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#endregion
using System;
using System.Collections.Generic;
using JiraGit.Common.Interfaces;
using JiraGit.Jira.Jira;
using CSharpTest.Net.Serialization;
using Atlassian.Jira;
using System.Linq;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Net;
using System.Collections;

namespace JiraGit.Jira
{
    class JiraConnection : IIssuesServiceConnection
	{
		const string ALL_USERS_KEY = "__ALL_USERS__";
		readonly INameValueStore _store = new CSharpTest.Net.Serialization.StorageClasses.RegistryStorage();
		readonly string _userName, _password, _rootUrl;
		readonly bool _lookupUsers;
		readonly JiraUser _currentUser;
		readonly Dictionary<string, JiraUser> _knownUsers;
		readonly Dictionary<string, JiraStatus> _statuses;
        readonly Converter<string, string> _settings;

		readonly JiraSoapServiceService _service;
		private string _token;
        Atlassian.Jira.Jira jira;	// This is the object that interfaces with the atlassian.net-sdk library.

		public JiraConnection(string url, string userName, string password, Converter<string, string> settings)
		{
      Log.Verbose("Creating a new connection");
			_rootUrl = url.TrimEnd('\\', '/');
			int offset = _rootUrl.LastIndexOf("/rpc/soap/jirasoapservice-v2");
			if (offset > 0)
				_rootUrl = _rootUrl.Substring(0, offset);

            Log.Info("Root Url: {0}", _rootUrl);
            _settings = settings;
			_knownUsers = new Dictionary<string, JiraUser>(StringComparer.OrdinalIgnoreCase);
			_lookupUsers = StringComparer.OrdinalIgnoreCase.Equals(settings("resolveUserNames"), "true");
            Log.Info("LookUp Users: {0}", _lookupUsers);
            
            LoadUsers();
			_statuses = new Dictionary<string, JiraStatus>(StringComparer.Ordinal);

			_userName = userName;
			_password = password;
            Log.Verbose("Creating a new internal Soap Service");
      _service = new JiraSoapServiceService();
      Log.Verbose("Service Created");
      _service.Url = _rootUrl + "/rpc/soap/jirasoapservice-v2";
      _service.UseDefaultCredentials = true;
      if (!String.IsNullOrEmpty(settings("jira:proxyurl")))
            {
                System.Net.ICredentials proxyAuth = System.Net.CredentialCache.DefaultCredentials;
                UriBuilder proxyuri = new UriBuilder(settings("jira:proxyurl"));
                if(!String.IsNullOrEmpty(proxyuri.UserName))
                {
                    proxyAuth = new System.Net.NetworkCredential(proxyuri.UserName, proxyuri.Password);
                    proxyuri.Password = proxyuri.UserName = String.Empty;
                }
                _service.Proxy = new System.Net.WebProxy(proxyuri.Uri);
                _service.Proxy.Credentials = proxyAuth;
            }

		    _token = null;

            Log.Verbose("Connecting...");
			Connect();
            Log.Verbose("Connection Successfull");
			_currentUser = GetUser(_userName);

            Log.Verbose("Getting Statuses");

      foreach (IssueStatus status in jira.Statuses.GetStatusesAsync().Result)
      {// Convert IssueStatus to RemoteStatus
                RemoteStatus rs = new RemoteStatus { id = status.Id, name = status.Name };
                _statuses[rs.id] = new JiraStatus(rs);
            }
            Log.Verbose("JiraConnection(): _statuses.Count = {0}", _statuses.Count);
            Log.Verbose("Finished creating a new connection");
		}

		private void LoadUsers()
		{
			string usersList;
            // Next line gets the value from the Registry at: Computer/HKEY_USERS/.../Software/httpstortoisegit.org/TortoiseGit/JiraGit.Jira.JiraConnection
            if (_store.Read(this.GetType().FullName, ALL_USERS_KEY, out usersList))
			{
				foreach (string suser in usersList.Split(';'))
				{
					if (_lookupUsers)
					{
						string fullName;
						if (_store.Read(this.GetType().FullName, suser, out fullName))
							_knownUsers[suser] = new JiraUser(suser, fullName);
					}
					else
						_knownUsers[suser] = new JiraUser(suser, suser);
				}
			}
		}

		public void Dispose()
		{
			try { if(!String.IsNullOrEmpty(_token)) _service.logout(_token); }
			catch { }
			finally { _token = null; }

			_service.Dispose();
		}

		protected string Token { get { return _token; } }
		protected JiraSoapServiceService Service { get { return _service; } }

		private void Connect()
        {
            Log.Verbose("About to call Atlassian.Jira.Jira.CreateRestClient(). This does not connect to JIRA");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
      jira = Atlassian.Jira.Jira.CreateRestClient(_rootUrl, _userName, _password, null);

            //_token=jira.GetAccessToken();// Tokens are no longer used with REST. _token = "<Unused>"
            //Log.Verbose("_token is {0}", _token);

            try
            {
                Log.Verbose("About to make an actual connection to JIRA to test out username and password.");
                //foreach (var project in jira.GetProjects())
                foreach (var project in jira.Projects.GetProjectsAsync().Result )
                {
                    Log.Verbose("Project = {0}.", project.Name);
                }
            }
            catch (Exception e)
            {
                Log.Error(e);
                throw new ApplicationException("Access denied: Connection issue. Possibly bad username or password.");
            }
        }

        public IIssueUser CurrentUser
		{
			get { return _currentUser; }
		}

		public IIssueFilter[] GetFilters()
		{
            List<IIssueFilter> filters = new List<IIssueFilter>();

            try
            {
                foreach (Atlassian.Jira.JiraFilter JNE in jira.Filters.GetFavouritesAsync().Result)
                {  // Need to convert a JiraNamedEntitiy to RemoteFilter
                    RemoteFilter filter = new RemoteFilter { name = JNE.Name, id = JNE.Id };
                    Log.Info("The filter is {0}", filter.name);
                    filters.Add(new JiraFilter(this, filter));
                }
			}
			catch (Exception e) { Log.Warning(e); }

			filters.Sort(new NameSorter<IIssueFilter>());

            //if (new Version(jiraInfo.version) < new Version("4.0"))
            filters.Add(new JiraAllFilter(this));

            return filters.ToArray();
		}

		public IIssueUser[] GetUsers()
		{
			return new List<JiraUser>(_knownUsers.Values).ToArray();
		}

        internal JiraUser GetUser(string name) 
		{
      JiraUser user;

      if (String.IsNullOrEmpty(name))
				return JiraUser.Unknown;

			if (!_knownUsers.TryGetValue(name, out user))
			{
                if (_lookupUsers)
                {

          var j = jira.Users.GetMyselfAsync(default).Result;
          Atlassian.Jira.JiraUser userAtl = j;
          string accountId = userAtl.AccountId;
          j = jira.Users.GetUserAsync(accountId ).Result;
          //Task<Atlassian.Jira.JiraUser> j = jira.GetUserAsync(name);
                    string h = j.DisplayName;
                    _knownUsers.Add(name, user = new JiraUser(name, h));
                }
                else
                    _knownUsers.Add(name, user = new JiraUser(name, name));

				_store.Write(this.GetType().FullName, user.Id, user.Name);
				_store.Write(this.GetType().FullName, ALL_USERS_KEY,
					String.Join(";", new List<String>(_knownUsers.Keys).ToArray()));
			}
            return user;
		}

		internal JiraStatus GetStatus(string status)
		{
			JiraStatus js;
			if (status != null && _statuses.TryGetValue(status, out js))
				return js;
            return JiraStatus.Unknown;
		}

		internal void ViewIssue(JiraIssue issue)
		{
			string url = String.Format("{0}/browse/{1}", _rootUrl, issue.DisplayId);

			try { System.Diagnostics.Process.Start(url); }
			catch (Exception e) 
			{ Log.Error(e, "Failed to view issue at uri = {0}.", url); }
		}

        internal List<JiraIssue> ConvertToListJiraRemoteIssue(IEnumerable<Issue> issuesGmoore)
        {
            List<JiraIssue> issues = new List<JiraIssue>();

            foreach (Issue I in issuesGmoore)
            {
                // Converting an Atlassian.Jira.Issue to JiraGit.Jira.Jira.RemoteIssue

                RemoteIssue remote = new RemoteIssue
                {
                    summary = I.Summary,
                    assignee = I.Assignee,
                    reporter = I.Reporter,
                    updated = I.Updated,
                    created = I.Created,
                    project = I.Project,
                    description = I.Description,
                    environment = I.Environment,
                    votes = I.Votes,
                    duedate = I.DueDate,
                    id = I.JiraIdentifier
                };

                // got the following code from /c/devLicenseGeneration/atlassian.net-sdk/Atlassian.Jira/Issue.cs

                remote.key = I.Key != null ? I.Key.Value : null;

                if (I.Status != null)
                {
                    remote.status = I.Status.Id; // Using Status.Id rather than Status.Name, helped with the populating the drop down statuses box
                }
                if (I.Resolution != null)
                {
                    remote.resolution = I.Resolution.Id;
                }
                if (I.Priority != null)
                {
                    remote.priority = I.Priority.Id;
                }
                if (I.Type != null)
                {
                    remote.type = I.Type.Id;
                }

                if (I.AffectsVersions.Count > 0)
                {
                    List<RemoteVersion> remoteVersions = new List<RemoteVersion>();
                    foreach (string s in I.AffectsVersions.Select(v => v.Name).ToArray())
                    {
                        remoteVersions.Add(new RemoteVersion { name = s });
                    }
                    remote.affectsVersions = remoteVersions.ToArray();
                }
                
                
                if (I.FixVersions.Count > 0)
                {
                    List<RemoteVersion> remoteVersions = new List<RemoteVersion>();
                    foreach (string s in I.FixVersions.Select(v => v.Name).ToArray())
                    {
                        remoteVersions.Add(new RemoteVersion { name = s });
                    }
                    remote.fixVersions = remoteVersions.ToArray();
                }


                /*
                if (I.Components.Count > 0)
                {
                    remote.components = I.Components.Select(c => c.Name).ToArray();
                }

                if (I.CustomFields.Count > 0)
                {
                    remote.customFieldValues = I.CustomFields.Select(f => new RemoteCustomFieldValue()
                    {
                        customfieldId = f.Id,
                        values = f.Values
                    }).ToArray();
                }
                */
                /*
                Log.Info("Inside GetAllIssues: {0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13}.",
                    remote.key,
                    remote.summary,
                    remote.assignee,
                    remote.reporter,
                    remote.updated,
                    remote.created,
                    remote.project, 
                    remote.description,
                    remote.environment, 
                    remote.votes,
                    remote.duedate,
                    remote.status,
                    remote.id,
                    remote.resolution
                );
                */
                issues.Add(new JiraIssue(this, remote));
            }  // end foreach

            return issues;
        }

        internal IIssue[] GetIssuesByFilter(JiraFilter filter, int offsett, int maxNumber)
        {
            Log.Info("Entering GetIssuesByFilter(filter.Name={0}, offsett={1}, maxNumber={2})", filter.Name, offsett, maxNumber);
            Log.Info("About to send query to JIRA.");
      var issuesFromFilter = jira.Filters.GetIssuesFromFilterAsync(filter.Id, maxNumber,offsett).Result;
      Log.Info("Inside GetIssuesByFilter: length of collection is {0}.", issuesFromFilter.Count());
            JiraIssue[] j = ConvertToListJiraRemoteIssue(issuesFromFilter).ToArray();
            Log.Info("Exiting GetIssuesByFilter(). Done putting query results into variables. Length of collection is {0}.", issuesFromFilter.Count());
            return j;
        }
        
        internal IIssue[] GetAllIssues(string text, int offsett, int maxNumber)
		{
            Log.Info("Entering GetAllIssues(text={0}, offsett={1}, maxNumber={2})", text, offsett, maxNumber);
            Log.Info("About to send query to JIRA.");

            // Determine if user is searching for a key, by testing to see if it has the correct pattern: alpha-numeric, a dash, then numeric
            // Otherwise JIRA will cause an exception of "The issue key 'VEST-711f5' for field 'key' is invalid."
            string jql;
            if ( Regex.IsMatch(text, @"^[a-zA-Z0-9].*-[0-9].*$") )
                jql = "(text ~ '" + text + "' ) OR (key = '" + text + "') ORDER BY key";
            else
                jql = "(text ~ '" + text + "' ) ORDER BY key";

            /* could not get this to work:
            var issuesGmoore = from i in jira.Issues
	              where (jql)
                  orderby i.Created
                  select i;
//            where i.Description.Contains(text) i.Key.Value.Contains(text)
//            where  i.Key.Value.Contains(text)
            */

      var issuesFromJql = jira.Issues.GetIssuesFromJqlAsync(jql, maxNumber).Result;
      JiraIssue[] j = ConvertToListJiraRemoteIssue(issuesFromJql).ToArray();
            Log.Info("Exiting GetAllIssues(): Done putting query results into variables. Length of collection is {0}.", issuesFromJql.Count());
            return j;
        }

        internal void AddComment(JiraIssue issue, string comment)
		{
			if (String.IsNullOrEmpty(comment)) return;
      Comment rc = new Comment();
      rc.Author = CurrentUser.Id;
      rc.Body = comment;

      jira.Issues.AddCommentAsync(issue.DisplayId, rc);
		}

		internal JiraAction [] GetActions(JiraIssue issue)
		{
			List<JiraAction> results = new List<JiraAction>();
			try
			{
        IEnumerable <IssueTransition> actionsAvailable = jira.Issues.GetActionsAsync(issue.DisplayId, true, default).Result;
        if (actionsAvailable != null)
        foreach (IssueTransition item in actionsAvailable)
             results.Add(new JiraAction(new RemoteNamedObject {id = item.Id, name = item.Name }));
   
      }

      catch (Exception e) { Log.Error(e); }
			return results.ToArray ();
		}

		private string FindFixResolution()
		{
      IEnumerable<IssueResolution> resolutions = jira.Resolutions.GetResolutionsAsync().Result;
      foreach (IssueResolution res in resolutions)
			{
				if (res.Name.IndexOf("fix", StringComparison.OrdinalIgnoreCase) >= 0)
					return res.Id;
       
			}
			throw new ApplicationException("Unable to locate a resolution containing the text 'fix'.");
		}

    internal void ProcessAction(JiraIssue  issue, IIssueAction action, IIssueUser assignTo)
    {
      List<RemoteFieldValue> actionParams = new List<RemoteFieldValue>();

      IEnumerable<IssueTransition> actionsAvailable = jira.Issues.GetActionsAsync(issue.DisplayId, true, default).Result;
      foreach (IssueTransition item in actionsAvailable)
        { 
           if (item.Name == action.Name)
          { 
            foreach (KeyValuePair<string,IssueFieldEditMetadata> field in item.Fields)
            {
                RemoteFieldValue param = new RemoteFieldValue();
                string paramName = param.id = field.Key;

                if (StringComparer.OrdinalIgnoreCase.Equals("Resolution", field.Value))
                    param.values = new string[] { FindFixResolution() };
                else if (StringComparer.OrdinalIgnoreCase.Equals("Assignee", field.Value))
                    param.values = new string[] { assignTo.Id };
                else if (StringComparer.OrdinalIgnoreCase.Equals("Worklog", paramName))	// JIRA 4.1 - worklogs are required!
                    continue;
                else
                {
                    param.values = issue.GetFieldValue(paramName);
                    if (param.values == null || param.values.Length == 0 || (param.values.Length == 1 && param.values[0] == null))
                    {
                        string setting = _settings(String.Format("{0}:{1}", action.Name, field.Value));
                        if(setting != null)
                            param.values = new string[] { setting };
                    }
                }

                actionParams.Add(param);
            }
          }
        }
      var updates = new WorkflowTransitionUpdates() { Comment = "Comment with Trans" };

         Issue ajIssue = ConvertJiraIssueToAtlassianIssue(issue);
      jira.Issues.ExecuteWorkflowActionAsync(ajIssue, action.Id, updates);
    }
    internal Issue ConvertJiraIssueToAtlassianIssue(JiraIssue issue)
    {
      Atlassian.Jira.Remote.RemoteIssue remIssue = new Atlassian.Jira.Remote.RemoteIssue();
      remIssue.assignee = issue.AssignedTo.Name;
      remIssue.reporter = issue.ReportedBy.Name;
      remIssue.updated = issue.LastModifiedOn;
      remIssue.created = issue.CreatedOn;
      remIssue.description = issue.FullDescription;
      remIssue.id = issue.Id;
      remIssue.key = issue.DisplayId;
      return new Issue(jira, remIssue);
    }
    internal void ProcessWorklog(JiraIssue issue, string timeSpent, TimeEstimateRecalcualationMethod method, string newTimeEstimate, string comment)
        {
            //var remoteWorklog = new RemoteWorklog();
            //remoteWorklog.comment = "Time logged";
            //remoteWorklog.timeSpent = timeSpent;
            //remoteWorklog.startDate = DateTime.Now;
        Worklog remoteWorklog = new Worklog(timeSpent, DateTime.Now, comment);


            switch (method)
            {
                case TimeEstimateRecalcualationMethod.AdjustAutomatically:
          jira.Issues.AddWorklogAsync(issue.DisplayId, remoteWorklog, WorklogStrategy.AutoAdjustRemainingEstimate);
                    break;

                case TimeEstimateRecalcualationMethod.DoNotChange:
          jira.Issues.AddWorklogAsync(issue.DisplayId, remoteWorklog, WorklogStrategy.RetainRemainingEstimate);

                    break;
                case TimeEstimateRecalcualationMethod.SetToNewValue:
          jira.Issues.AddWorklogAsync(issue.DisplayId, remoteWorklog, WorklogStrategy.NewRemainingEstimate);

                    break;
                default:
                    throw new ArgumentOutOfRangeException("ProcessWorklog");
            }
        }
	}

}
