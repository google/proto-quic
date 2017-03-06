# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story
from telemetry.util import js_template


URL_LIST = [
    ('Polymer', 'http://todomvc.com/examples/polymer'),
    ('AngularJS', 'http://todomvc.com/examples/angularjs'),
    ('React', 'http://todomvc.com/examples/react'),
    ('Backbone.js', 'http://todomvc.com/examples/backbone'),
    ('Ember.js', 'http://todomvc.com/examples/emberjs'),
    ('Closure', 'http://todomvc.com/examples/closure'),
    ('GWT', 'http://todomvc.com/examples/gwt'),
    ('Dart', 'http://todomvc.com/examples/vanilladart/build/web'),
    ('Vanilla JS', 'http://todomvc.com/examples/vanillajs'),
]

INTERACTION_NAME = 'Interaction.AppLoad'


class TodoMVCPage(page_module.Page):

  def __init__(self, url, page_set, name):
    super(TodoMVCPage, self).__init__(
        url=url, page_set=page_set, name=name,
        shared_page_state_class=shared_page_state.SharedDesktopPageState)
    # TODO(jochen): This interaction does not include the
    # WindowProxy::initialize portion before the commit. To fix this, we'll
    # have to migrate to TBMv2.
    self.script_to_evaluate_on_commit = js_template.Render(
        'console.time({{ label }});', label=INTERACTION_NAME)

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript(
        """
        this.becameIdle = false;
        this.idleCallback = function(deadline) {
            if (deadline.timeRemaining() > 20)
                this.becameIdle = true;
            else
                requestIdleCallback(this.idleCallback);
        };
        requestIdleCallback(this.idleCallback);
        """
    )
    action_runner.WaitForJavaScriptCondition('this.becameIdle === true')
    action_runner.ExecuteJavaScript(
        'console.timeEnd({{ label }});', label=INTERACTION_NAME)


class TodoMVCPageSet(story.StorySet):

  """ TodoMVC examples """

  def __init__(self):
    super(TodoMVCPageSet, self).__init__(
      archive_data_file='data/todomvc.json',
      cloud_storage_bucket=story.PUBLIC_BUCKET)

    for name, url in URL_LIST:
      self.AddStory(TodoMVCPage(url, self, name))
