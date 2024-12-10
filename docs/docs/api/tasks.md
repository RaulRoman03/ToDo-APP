# Tasks API

Allows users to manage their tasks using a RESTful API.

---

## Endpoints
- **GET /api/tasks**
- Description: Gets all the user's tasks.
- Parameters: Authentication token.
- Response: List of tasks.

- **POST /api/tasks**
- Description: Creates a new task.
- Parameters: `title`, `description`, `due_date`.
- Response: Details of the created task.