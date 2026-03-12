# API Tracker - Google Auth + Static Dashboard Implementation TODO

**Status: Plan Approved. Implementing step-by-step.**

## Implementation Steps

### Backend Setup (Google OAuth)

✅ **Step 1**: Update root `package.json` deps + scripts. Run `npm install`.
✅ **Step 2**: Create `.env` with Google OAuth placeholders.

✅ **Step 3**: Update `index.js` - Add Passport Google OAuth, sessions, routes (/auth/google, callback, logout, /api/user), serve frontend/dist.

### Frontend Dashboard

✅ **Step 4**: Create dirs `frontend/src/components/`, `frontend/src/contexts/`.
✅ **Step 5**: Create `frontend/src/contexts/AuthContext.jsx`.
✅ **Step 6**: Create `frontend/src/components/Dashboard.jsx` (static mock: projects, APIs table, test/export).

✅ **Step 7**: Update `frontend/src/App.jsx` (Router, routes: /dashboard protected, nav login state).
✅ **Step 8**: Update `frontend/src/main.jsx` (AuthProvider + Router).

### Finalization

✅ **Step 9**: Update `README.md` (setup instr, Google console steps).

- [ ] **Step 10**: Test: `npm run dev` → Google login → dashboard.

**Next**: Update .env with Google creds → `cd frontend && npm run dev` (backend running) → Test login/dashboard.

**Completed Steps Will Be Marked ✅**
