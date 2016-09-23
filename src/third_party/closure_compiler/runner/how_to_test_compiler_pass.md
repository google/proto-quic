Run Java tests
==============

1. Build Closure Compiler jar with all tests:

        git clone https://github.com/google/closure-compiler.git
        cd closure-compiler
        ant all-classes-jar

2. Add test file to Eclipse and run tests in it.
  - Launch Eclipse.
  - File -> New -> Java Project.
  - Enter any project name, click "Next >".
  - On the tab "Source" click on the icon "Link additional source to project".
  - Select "third_party/closure_compiler/runner/test", click "Finish".
  - Click on the icon  "Link additional source to project" once again.
  - Select "third_party/closure_compiler/runner/src", type a name "src2",
      click "Finish".
  - On the tab "Libraries" click "Add External JARs...".
  - Select "closure-compiler/build/compiler.jar", click "Finish" two times.
  - Open the class test/com.google.javascript.jscomp/ChromePassTest.java.
  - Run As -> JUnit Test.


Run Python tests
================

Run in Shell:

    ./third_party/closure_compiler/runner/build_runner_jar.py
    ./third_party/closure_compiler/compiler_customization_test.py
