# Troubleshooting

## I can't log in

1. Make sure the username and password are correct.
2. Check that your internet connection is active.
3. If you forgot your password, use the "Recover password" option.

## Application does not load correctly

1. Check that the application server is running without errors.
2. Make sure that the environment variables are set correctly, especially those related to the database.

## Database changes are not reflected

1. Make sure that the database is running.
2. Check that the connection parameters in `variables.env` are correct.
3. Check the server logs for possible connection errors.

## Error deleting a task

1. Make sure that the task is not being used in another process.
2. Check the database permissions and make sure that the user has the appropriate permissions to delete records.

## What to do if the application is not responding?

1. Check the browser console or server logs for errors.
2. If the error persists, try restarting the server and verify that all dependencies are correctly installed.