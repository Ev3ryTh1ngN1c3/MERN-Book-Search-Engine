 // import the path module
const path = require('path');
const express = require('express');
// import ApolloServer
const { ApolloServer } = require('apollo-server-express');
// middleware function for authentication
const { authMiddleware } = require('./utils/auth');
// import our typeDefs and resolvers
const { typeDefs, resolvers } = require('./schemas');
const db = require('./config/connection');

const PORT = process.env.PORT || 3001;
const app = express();

// create a new Apollo server and pass in our schema data
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // context will be used for token authentication
  context: ({ req, res }) => authMiddleware(req, res),
});

// integrate our Apollo server with the Express application as middleware
server.applyMiddleware({ app });

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Serve up static assets
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
}

// Wildcard route to serve React front-end in production
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/build/index.html'));
});

db.once('open', () => {
  app.listen(PORT, () => {
    console.log(`API server running on port ${PORT}!`);
    // Log where we can test our GraphQL API
    console.log(`Use GraphQL at http://localhost:${PORT}${server.graphqlPath}`);
  });
});