@echo off
echo ================================================
echo  DoubleCheck - Fix Git + Deploy to Railway
echo ================================================
echo.

echo Step 1: Remove all cached files from git tracking...
git rm -r --cached .
echo Done.
echo.

echo Step 2: Re-add all files (gitignore will now apply)...
git add .
echo Done.
echo.

echo Step 3: Commit...
git commit -m "Fix gitignore - remove cached files, add nixpacks config"
echo Done.
echo.

echo Step 4: Push to GitHub...
git push
echo Done.
echo.

echo ================================================
echo  All done! Now go to Railway and redeploy.
echo ================================================
pause
