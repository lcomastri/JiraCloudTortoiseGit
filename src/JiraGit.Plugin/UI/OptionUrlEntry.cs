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
using System.Windows.Forms;

namespace JiraGit.Plugin
{
	partial class OptionUrlEntry : Form
	{
		public OptionUrlEntry(string serviceUri, string desc)
		{
			InitializeComponent();
			
			ServiceUri.TextChanged += new EventHandler(ServiceUri_TextChanged);
			ServiceUri.Text = String.Format("{0}", serviceUri);
			_message.Text = desc;
		}

		void ServiceUri_TextChanged(object sender, EventArgs e)
		{
			Uri uri;
			this.okButton.Enabled = Uri.TryCreate(ServiceUri.Text, UriKind.Absolute, out uri);
		}

		protected override void OnShown(EventArgs e)
		{
			base.OnShown(e);
		}


	}
}
