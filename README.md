# ct-download
Download certificates from CT

## Usage

Go to `ctsync-pull` and run  `go build`. 

```
Usage of ./ctsync-pull:
  -config string
        The configuration file for log servers (default "config.json")
  -cpu-profile
        run cpu profiling
  -db string
        Path to the SQLite file that stores log sync progress (default "ctsync-pull.db")
  -fetchers int
        Number of workers assigned to fetch certificates from each server (default 1)
  -gomaxprocs int
        Number of processes to use (default 1)
  -matchers int
        Number of workers assigned to parse certs from each server (default 1)
  -mem-profile
        run memory profiling
  -output-dir string
        Output directory to store certificates (default "deduped-certs")

```
