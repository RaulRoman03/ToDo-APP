# Authentication API

Provides endpoints to handle user authentication.

---

## Endpoints
- **POST /api/auth/register**
- Description: Registers a new user.
- Parameters: `email`, `password`.
- Response: Authentication token.

- **POST /api/auth/login**
- Description: Logs in to the application.
- Parameters: `email`, `password`.
- Response: Session token.

- **POST /api/auth/logout**
- Description: Logs out.
- Parameters: None.