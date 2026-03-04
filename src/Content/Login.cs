namespace Garde;

public static partial class Content
{
    public const string Login = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Login</title>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500&family=DM+Serif+Display&display=swap" rel="stylesheet"/>
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          background: #f4f1ec;
          font-family: 'DM Sans', sans-serif;
          color: #1a1714;
        }

        .card {
          background: white;
          padding: 2.5rem;
          border-radius: 12px;
          width: 100%;
          max-width: 480px;
          box-shadow: 0 4px 24px rgba(0,0,0,0.07);
        }

        h1 {
          font-family: 'DM Serif Display', serif;
          font-size: 1.8rem;
          margin-bottom: 0.3rem;
        }

        .subtitle {
          font-size: 0.85rem;
          color: #888;
          margin-bottom: 2rem;
        }

        .error {
          font-size: 0.85rem;
          color: #c0492b;
          margin-bottom: 1.2rem;
          display: none;
        }

        .error:not(:empty) {
          display: block;
        }

        label {
          display: block;
          font-size: 0.78rem;
          font-weight: 500;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: #666;
          margin-bottom: 0.4rem;
        }

        input {
          width: 100%;
          padding: 0.75rem 1rem;
          border: 1px solid #ddd;
          border-radius: 8px;
          font-family: 'DM Sans', sans-serif;
          font-size: 0.95rem;
          outline: none;
          transition: border-color 0.2s, box-shadow 0.2s;
          margin-bottom: 1.2rem;
        }

        input:focus {
          border-color: #c0492b;
          box-shadow: 0 0 0 3px rgba(192,73,43,0.1);
        }

        button {
          width: 100%;
          padding: 0.85rem;
          background: #c0492b;
          color: white;
          border: none;
          border-radius: 8px;
          font-family: 'DM Sans', sans-serif;
          font-size: 0.9rem;
          font-weight: 500;
          cursor: pointer;
          transition: background 0.2s;
        }

        button:hover { background: #a83d23; }

        @media (max-width: 480px) {
          body { background: white; align-items: flex-start; padding-top: 3rem; }
          .card { box-shadow: none; border-radius: 0; padding: 1.5rem; }
        }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Sign in</h1>
        <p class="subtitle">Enter your credentials to continue.</p>

        <form method="POST" action="/login">
          <input type="hidden" name="csrf" value="{{CSRF_TOKEN}}" />
          <input type="hidden" name="redirect" value="{{REDIRECT_URL}}" />
          <p class="error" id="error-msg">{{ERROR_MESSAGE}}</p>

          <label for="username">Username</label>
          <input type="text" id="username" name="username" placeholder="Enter your username" autocomplete="username" required onkeydown="if(event.key==='Enter')this.form.submit()"/>

          <label for="password">Password</label>
          <input type="password" id="password" name="password" placeholder="••••••••" autocomplete="current-password"/>

          <button type="submit">Sign in</button>
        </form>
      </div>
    </body>
    </html>
    
    """;
}