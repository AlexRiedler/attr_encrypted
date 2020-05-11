#!/usr/bin/env sh -e

for RUBY in 2.5.8 2.6.6 2.7.1
do
  for RAILS in 5.2.4.2 6.0.3
  do
    RBENV_VERSION=$RUBY ACTIVERECORD=$RAILS bundle && bundle exec rake
  done
done
