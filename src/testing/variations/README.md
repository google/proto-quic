# Field Trial Testing Configuration

This directory contains the field trial configuration used to ensure testing
coverage of the experiments defined in `fieldtrial_testing_config.json`.

Note that these apply specifically for Chromium builds. Chrome branded /
official builds do not use these definitions.

The first available experiment after platform filtering and concatenation is the
default experiment for Chromium builds. This experiment is also used for perf
bots and browser tests in the waterfall.

## Config File Format

```json
{
    "StudyName": [
        {
            "platforms": [Array of Strings of Valid Platforms for These Experiments],
            "experiments": [
                {
                    "//0": "Comment Line 0. Lines 0-9 are supported.",
                    "name": "ExperimentName",
                    "params": {Dictionary of Params},
                    "enable_features": [Array of Strings of Features],
                    "disable_features": [Array of Strings of Features]
                },
                ...
            ]
        },
        ...
    ],
    ...
}
```

The config file is a dictionary at the top level mapping a study name to an
array of *study configurations*. The study name should match the Field Trial
study name.

### Study Configurations

Each *study configuration* is a dictionary containing both `platform` and
`experiments`.

`platform` is an array of strings of valid platforms and the
strings may be `android`, `chromeos`, `ios`, `linux`, `mac`, or `windows`.

`experiments` is an array containing the *experiments*.

The converter uses the platforms array to determine what experiments to include
for the study. All matching platforms will have their experiments concatenated
together for the study.

### Experiments (Groups)
Each *experiment* is a dictionary that must contain the `name` key, identifying
the experiment group name which should match the Field Trial experiment group
name.

The remaining keys, `params`, `enable_features`, and `disable_features` are
optional.

`params` is a dictionary mapping parameter name to parameter.

`enable_features` and `disable_features` indicate which features should be
enabled and disabled respectively through the
[Feature List API](https://cs.chromium.org/chromium/src/base/feature_list.h). As
a reminder, as the variations framework does not actually fetch the Field Trial
definitions from the server for Chromium builds, so any feature enabling or
disabling must be done here.

#### Comments

Each experiment may have up to 10 lines of comments. The comment key must be of
the form `//N` where `N` is between 0 and 9.

```json
{
    "AStudyWithExperimentComment": [
        {
            "platforms": ["chromeos", "linux", "mac", "win"],
            "experiments": [
                {
                    "//0": "This is the first comment line.",
                    "//1": "This is the second comment line.",
                    "name": "DesktopExperiment"
                }
            ]
        }
    ]
}
```

### Specifying Different Experiments for Different Platforms
Simply specify two different study configurations in the study:

```json
{
    "DifferentExperimentsPerPlatform": [
        {
            "platforms": ["chromeos", "linux", "mac", "win"],
            "experiments": [{ "name": "DesktopExperiment" }]
        },
        {
            "platforms": ["android", "ios"],
            "experiments": [{ "name": "MobileExperiment" }]
        }
    ]
}
```

## Presubmit
The presubmit tool will ensure that your changes follow the correct ordering and
format.
