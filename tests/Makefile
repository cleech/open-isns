#
# Simple makefile to run regression tests, and to
# document how to run them.

#
# Each test is a TestCase in test-isns.py. Run a single test
# using:
#
#     ./test-isns.py [OPTIONS] TestNN	(where NN is '00' through '11')
#
# Run all the tests with:
#
#     ./test-isns.py [OPTIONS]
#
# Use:
#
#    ./test-isns.py -h
#
# To prin the command-line options supported.
#
# The default is to be fairly quiet. Use "-v" to be more
# verbose, with output more like the previous perl tests.

# All test related data is kept in /tmp/isns-test, with a
# subdirectory for each test.  For instance, Test01 will create
#  /tmp/isns-test/Test01/server0
#  /tmp/isns-test/Test01/client1
#  /tmp/isns-test/Test01/dump
#
# The server and client directories will contain configuration
# data, logfiles, and (for the server) the Unix socket, the
# PID file, and the database.
#
# The dump directory contains snapshots of the on-disk database
# for each test stage (if the test stage involves a verification
# of the database).
#
# The reference data for the tests is in the "data" subdirectory,
# e.g. data/Test01/* for Test01.
#

tests:
	@echo running tests using security -- takes about 2 minutes
	./test-isns.py -s

quick: tests-no-security

tests-no-security:
	@echo running tests without security -- takes about 2 minutes
	./test-isns.py
