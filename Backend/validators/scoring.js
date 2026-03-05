exports.calculateScore = ({
  syntaxValid,
  domainValid,
  mxValid,
  smtp,
  disposable,
  roleBased,
  catchAll
}) => {

  let score = 0;

  // Positive points
  if (syntaxValid) score += 20;
  if (domainValid) score += 15;
  if (mxValid) score += 20;
  if (smtp) score += 30;
  if (!disposable) score += 10;
  if (!roleBased) score += 5;

  // Negative points
  if (disposable) score -= 40;
  if (catchAll) score -= 25;
  if (roleBased) score -= 10;

  // Limit score between 0 and 100
  if (score < 0) score = 0;
  if (score > 100) score = 100;

  return score;
};
