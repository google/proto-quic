# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class RevisionState(object):
  """Contains bisect state for a given revision.

  Properties:
    depot: The depot that this revision is from (e.g. WebKit).
    revision: Revision number (Git hash or SVN number).
    index: Position of the state in the list of all revisions.
    value: Value(s) returned from the test.
    perf_time: Time that a test took.
    build_time: Time that a build took.
    passed: Represents whether the performance test was successful at that
        revision. Possible values include: 1 (passed), 0 (failed),
        '?' (skipped), 'F' (build failed).
    external: If the revision is a 'src' revision, 'external' contains the
        revisions of each of the external libraries.
  """

  def __init__(self, depot, revision, index):
    self.depot = depot
    self.revision = revision
    self.index = index
    self.value = None
    self.perf_time = 0
    self.build_time = 0
    self.passed = '?'
    self.external = None

  # TODO(sergiyb): Update() to parse run_results from the RunTest.


class BisectState(object):
  """Represents a state of the bisect as a collection of revision states."""

  def __init__(self, depot, revisions):
    """Initializes a new BisectState object with a set of revision states.

    Args:
      depot: Name of the depot used for initial set of revision states.
      revisions: List of revisions used for initial set of revision states.
    """
    self.revision_states = []
    self.revision_index = {}

    index = 0
    for revision in revisions:
      new_state = self._InitRevisionState(depot, revision, index)
      self.revision_states.append(new_state)
      index += 1

  @staticmethod
  def _RevisionKey(depot, revision):
    return "%s:%s" % (depot, revision)

  def _InitRevisionState(self, depot, revision, index):
    key = self._RevisionKey(depot, revision)
    self.revision_index[key] = index
    return RevisionState(depot, revision, index)

  def GetRevisionState(self, depot, revision):
    """Returns a mutable revision state."""
    key = self._RevisionKey(depot, revision)
    index = self.revision_index.get(key)
    return self.revision_states[index] if index else None

  def CreateRevisionStatesAfter(self, depot, revisions, reference_depot,
                                reference_revision):
    """Creates a set of new revision states after a specified reference state.

    Args:
      depot: Name of the depot for the new revision states.
      revisions: List of revisions for the new revision states.
      reference_depot: Name of the depot for the reference revision state.
      reference_revision: Revision for the reference revision state.

    Returns:
      A list containing all created revision states in order as they were added.
    """
    ref_key = self._RevisionKey(reference_depot, reference_revision)
    ref_index = self.revision_index[ref_key]
    num_new_revisions = len(revisions)
    for entry in self.revision_states:
      if entry.index > ref_index:
        entry.index += num_new_revisions

    first_index = ref_index + 1
    for index, revision in enumerate(revisions, start=first_index):
      new_state = self._InitRevisionState(depot, revision, index)
      self.revision_states.insert(index, new_state)

    return self.revision_states[first_index:first_index + num_new_revisions]

  def GetRevisionStates(self):
    """Returns a copy of the list of the revision states."""
    return list(self.revision_states)
