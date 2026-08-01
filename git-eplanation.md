**Note: You will need to create the `b-023/test.md` file**

The claim that the permission system uses `.gitignore` permission pattern doesn't really hold
because i just tested it and this is the result.

The `b-023/test.md` is added to the gitignore file on the root folder as `**/test.md` the same pattern used for report.md in the `.claude/settings.json`.

- First test i ran `git status` on the root and it showed it wasn't tracked meaning it was ignored by git which is the correct and expected behaviour.

- Second test i cd into the `/b-023/answers` and ran git status, it also didn't track `test.md` showing that .gitignore works differenly from the way the current Claude-code Harness permission works. Because changing directory with git didn't change the permisson settings.
