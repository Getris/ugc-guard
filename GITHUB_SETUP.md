# Publish the repository on GitHub

## Recommended method

1. Sign in to GitHub and create a new **public** repository named `ugc-guard`.
2. Do not initialize it with a README, license, or `.gitignore`; those files already exist here.
3. Extract this archive and open a terminal in the extracted folder.
4. Run:

```bash
git init
git add .
git commit -m "Initial open-source release"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ugc-guard.git
git push -u origin main
```

5. Replace `zooplio` in `package.json`, README badges, and GitHub links with your actual GitHub username or organization name.
6. In GitHub repository settings, enable **Private vulnerability reporting** under Security.
7. Add repository topics: `typescript`, `security`, `ugc`, `moderation`, `spam`, `open-source`.

## Before publishing to npm

Choose an available package name. The scoped package `@zooplio/ugc-guard` requires access to the `zooplio` npm organization. Otherwise, use a name such as `zooplio-ugc-guard` and update the imports in the README.

Then run:

```bash
npm install
npm test
npm login
npm publish --access public
```

Never commit `.env` files, API keys, production URLs, private Zooplio source code, database schemas, user data, or infrastructure configuration.
