# based on: https://github.com/icorderi/kinetic-rust/blob/master/.travis-update-gh-pages.sh
# based on: http://sleepycoders.blogspot.se/2013/03/sharing-travis-ci-generated-files.html

# Only do it if not acting on a pull request.
if [ "$TRAVIS_BRANCH" = "master" ] && [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_RUST_VERSION" == "stable" ]; then

  GH_REPO="github.com/mrfloya/pam-auth.git"
  rev=$(git rev-parse --short HEAD)

  # Go to home and setup git
  cd $HOME
  git config --global user.email "travis@travis-ci.org"
  git config --global user.name "Travis"

  # Create empty git to overwrite previous commits
  mkdir docs
  cd docs
  git init
  git remote add upstream https://${GH_TOKEN}@${GH_REPO}

  # Copy the freshly built contents
  cp -Rf $TRAVIS_BUILD_DIR/target/doc/* .

  # add, commit and push files
  git add --all -f .
  git commit -m "Update gh-pages by travis build $TRAVIS_BUILD_NUMBER @$rev"
  git push -f upstream HEAD:gh-pages > /dev/null 2>&1
fi
