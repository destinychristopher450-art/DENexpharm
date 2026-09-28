# DENexpharm

DENexpharm is a pharmacy learning, quiz, practice, and competition platform designed for pharmacy students worldwide, with strong support for Nigerian pharmacy students.

## Main Features

- Pharmacy quiz and practice questions
- Multiple subjects and topics
- Explanations for questions
- Quick Practice mode
- Exam mode
- Timed quizzes
- Topic-based quizzes
- Weak-topic practice
- Practical/case-based questions
- XP and progress tracking
- Streaks and achievements
- Leaderboards
- Daily challenges
- Saved difficult questions
- GPA calculator
- Pharmacy library
- Pharmacopoeia learning concepts
- Pharmacy language assistant
- User accounts and authentication
- Premium features
- Advertising support
- Payment integration structure
- Admin functionality
- Scalable question-bank structure

## Technology

DENexpharm uses:

- Node.js
- Express.js
- HTML
- CSS
- JavaScript
- JSON database for MVP use
- PostgreSQL-compatible database structure for future production scaling

## Project Structure

DENexpharm/

- server.js
- package.json
- public/
  - index.html
- data/
  - db.json
  - questions.json
- schema.sql
- .env.example
- README.md

## Running Locally

Install Node.js 18 or newer.

Open a terminal inside the DENexpharm project folder and run:

npm install

Then start the application:

npm start

The application should normally be available at:

http://localhost:3000

## GitHub Deployment

1. Create a GitHub repository.
2. Extract the DENexpharm ZIP file.
3. Upload the contents of the DENexpharm folder to the GitHub repository.
4. Make sure package.json and server.js are in the main/root directory.
5. Make sure the public folder contains index.html.
6. Commit the files.

## Render Deployment

DENexpharm is designed to run as a Node.js/Express web service.

On Render:

1. Create a new Web Service.
2. Connect your GitHub repository.
3. Select the DENexpharm repository.
4. Use the following build command:

npm install

5. Use the following start command:

npm start

6. Select an appropriate Node.js environment.
7. Add the required environment variables.
8. Deploy the service.

Render will provide a public URL for the application after deployment.

## Environment Variables

Copy .env.example to .env when running locally.

Typical production variables may include:

PORT=3000

NODE_ENV=production

FRONTEND_ORIGIN=https://your-frontend-domain.com

DATABASE_URL=your_database_connection_string

PAYSTACK_SECRET_KEY=your_paystack_secret_key

PAYSTACK_PUBLIC_KEY=your_paystack_public_key

SESSION_SECRET=your_long_random_session_secret

Do not publish secret keys or passwords on GitHub.

## Database

The MVP includes JSON data files for simple development and testing.

For production use, PostgreSQL is recommended.

The included schema.sql provides the structure needed for a PostgreSQL database.

Possible production database providers include:

- Render PostgreSQL
- Neon
- Supabase

## Payments

The application contains the structure needed for premium/payment integration.

Before accepting real payments:

- Add your real payment provider credentials.
- Configure payment verification.
- Configure the webhook endpoint.
- Test transactions in the provider's test environment.
- Never expose secret payment keys in frontend code.

## Questions

The question bank is designed to be expanded.

Questions can eventually be organized by:

- Subject
- Topic
- Difficulty
- Year
- Country
- Question type
- Practical/case category

The platform can therefore be expanded from the initial question set to thousands or more questions.

## Free and Premium Features

The platform can support:

### Free

- Basic quizzes
- Selected questions
- Basic progress tracking
- Limited advertisements

### Premium

- Larger question bank
- Advanced mock examinations
- Detailed analytics
- Additional learning resources
- Premium practice modes
- Additional library features

Premium features should be configured and tested before real-world launch.

## Cloudflare

The current DENexpharm application uses Node.js and Express.

Therefore, the complete application should be deployed on a Node.js-compatible service such as Render.

Cloudflare Pages can be used for a separate static frontend, but the current Express server should not simply be uploaded to Cloudflare Pages as a normal Node.js server.

Cloudflare can also be added later for domain management, DNS, caching, or other services.

## Security

Before a public production launch:

- Use HTTPS.
- Use a strong SESSION_SECRET.
- Never commit .env files.
- Never expose payment secret keys.
- Use production database credentials.
- Configure CORS correctly.
- Keep dependencies updated.
- Enable appropriate rate limiting.
- Validate user input.
- Verify payment webhooks.
- Use secure session settings.

## Important

The application is an MVP foundation and should be thoroughly tested before accepting real users or payments.

Educational content should also be reviewed for accuracy before being used as official teaching material.

## Future Development

Future versions can include:

- 10,000+ questions
- 50,000+ questions
- 100,000+ questions
- PostgreSQL/Supabase production database
- Mobile application
- Advanced battle system
- Global pharmacy competitions
- More countries and curricula
- More languages
- Push notifications
- Advanced analytics
- Teacher/institution accounts
- Improved admin dashboard
- Payment subscriptions
- More pharmacy calculations
- AI-assisted learning features

## Project Goal

The long-term goal of DENexpharm is to provide a structured digital learning and competition environment for pharmacy students, combining learning, practice, revision, competition, and progress tracking in one platform.

---

DENexpharm

Pharmacy Learning. Practice. Competition.
