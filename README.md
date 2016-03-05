# Aerospike Telemetry

Aerospike Telemetry is a feature that sends certain anonymized usage information (such as: when clusters are created and destroyed, clusters size, cluster workload, how often queries are run, whether instances are deployed purely in-memory or with Flash) to Aerospike for research purposes. IP and MAC addresses are already anonymized when we receive the data. The Telemetry Agent collects information from running Community Edition server instances every 10 minutes. The data helps us to understand how the product is being used, identify issues, and create a better experience for you.

## It's Anonymous

Aerospike Telemetry only collects usage information - statistics about the running servers. Machine IP and MAC addresses (collected so we can track cluster members) are run through a one-way hash before sending so you cannot be identified. Neither your keys nor your data are ever sent.

## It's Easy to Verify and to Disable

Aerospike Telemetry runs as a separate process from the Aerospike server. Since it's a separate process - not hidden in complex server code - you can see the statistics it gathers, verify that it doesn't send any of your data, where it sends to, and how often. You can kill the process, you can create your own package that doesn't include the Python script, or you can edit a line in its configuration script so that it never starts. It's that simple.

## How Do I Turn Aerospike Telemetry Off?

There are two ways to enable and disable the Telemetry Agent:

### Directly Editing the Configuration File

If the server was installed via DEB or RPM, the configuration file can be found at `/etc/aerospike/telemetry.conf`. If you’re running the server from within the GitHub repository, the relevant configuration file can be found at `<repo path>/as/etc/telemetry_dev.conf`.

To disable (or enable) the Telemetry Agent, change the `disable` value in the configuration file to `true` (or `false`.)

### Using the Telemetry Agent Command Line Interface

If the server was installed via DEB or RPM package, run:

	$ python /opt/aerospike/telemetry/telemetry.py /etc/aerospike/telemetry.conf --disable

or

	$ python /opt/aerospike/telemetry/telemetry.py /etc/aerospike/telemetry.conf --enable

If you’re running from within the repository, run:

	$ python <repo path>/modules/telemetry/telemetry.py <repo path>/as/etc/telemetry_dev.conf --disable

or

	$ python <repo path>/modules/telemetry/telemetry.py <repo path>/as/etc/telemetry_dev.conf --enable

### Making the Change Take Effect

If Aerospike is already running when using either of the above methods, you must restart Aerospike (or just the Telemetry Agent) for the change to take effect:

	$ service aerospike restart           -- Under Sys V Init. (On most distros.)

or

	$ systemctl restart aerospike         -- Under systemd. (Currently the default on Red Hat EL7-based distros only.)

or

	$ service aerospike_telemetry restart

or, when ASD is run from within the open source tree (i.e., GitHub repo.):

	$ make stop start

## For More Information

For further information - including our promise to share the results of our research - see <http://aerospike.com/aerospike-telemetry>
