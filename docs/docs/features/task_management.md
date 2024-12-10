# Task Management

The main functionality of ToDo-APP is task management. This section describes how to work with tasks in the app.

## Creating a Task
To create a task, the user must provide a title and an optional description. The task will be added to their to-do list.

### Task Creation API
- **Method:** `POST`
- **Endpoint:** `/tasks`
- **Parameters:**
- `title` (string, required)
- `description` (string, optional)

#### Request example:
```json
{
"title": "Task 1",
"description": "Task 1 description"
}