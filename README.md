# SDN Final Project

This project implements a modified version of the SLICOTS algorithm on the Floodlight SDN controller that allows the user to configure different values for the `hard_timeout` parameter.

The Mininet script included in this project implements Scenario S1 as described in the SLICOTS paper.

The packet capture for different numbers of attackers over a 180 second period can be found in the `packet_captures` directory.

As of now, only packets captured from an unmodified Floodlight build have been generated.

## Results

![Scenario 1 Results](results/results_scenario1.PNG)

This is a comparison of the HTTP response time compared to the number of attackers.

## Usage

Start floodlight
```
java -jar target/floodlight.jar
```

Run Mininet Script
```
sudo python3 slicots_network_run_test.py
```

## References

```
R. Mohammadi, R. Javidan and M. Conti, "SLICOTS: An SDN-Based Lightweight Countermeasure for TCP SYN Flooding Attacks," in IEEE Transactions on Network and Service Management, vol. 14, no. 2, pp. 487-497, June 2017, doi: 10.1109/TNSM.2017.2701549.
```