# Lab 5 — Event-Driven Cybersecurity Pipeline

## Student

* Dror Sullam

## What I Ran

In this lab, I ran an event-driven cybersecurity pipeline using Docker Compose.

The pipeline included the following components:

* Kafka-compatible message broker
* Producer notebook
* Consumer / classifier notebook
* Local CSV output
* Statistics notebook
* Redpanda Console
* Jaeger tracing

The main flow was:

```text
Producer
  -> Kafka topic
  -> Consumer / Classifier
  -> Local CSV storage
  -> Statistics notebook
```

The pipeline successfully generated events, sent them through Kafka, consumed and classified them, and stored the results locally.

## Pipeline Output

The consumer created the following output file:

```text
classified_packets.csv
```

The Statistics notebook was able to read this file and produce basic analysis from the classified events.

This shows that the pipeline worked end-to-end: events were produced, transported, consumed, classified, stored, and then analyzed.

## Redpanda Console Inspection

I opened Redpanda Console at:

```text
http://localhost:8080
```

The Kafka topics were visible in the console. This allowed me to inspect the message-broker layer of the pipeline and confirm that events were being published through Kafka rather than passed directly between Python functions.

Redpanda Console helped verify that the event pipeline was active and that the producer and consumer were communicating through topics.

## Jaeger Trace Inspection

I opened Jaeger at:

```text
http://localhost:16686
```

After selecting a service and clicking **Find Traces**, traces were visible.

The traces helped show that the pipeline was not just producing a final CSV file. It also had observable internal stages, which is useful for debugging and understanding how events move through the system.

Tracing is important in event-driven systems because failures or delays may happen in different stages, such as event production, Kafka consumption, classification, or storage.

## Conceptual Questions

### Why is Kafka used instead of direct function calls?

Kafka is used because it decouples the producer from the consumer.

With direct function calls, the producer and consumer must both be available at the same time, and the producer must wait for the consumer to process the data. With Kafka, the producer can publish events to a topic, and the consumer can process them independently.

This makes the pipeline more flexible, more scalable, and more fault-tolerant. It also better matches real cybersecurity environments, where logs and events arrive continuously from many sources.

### What happens if the consumer is slower than the producer?

If the consumer is slower than the producer, messages can accumulate in Kafka.

This is one of the main benefits of using a message broker. Kafka can buffer events so the producer does not immediately fail just because the consumer is temporarily slower. However, if the consumer stays too slow for too long, lag will grow, storage usage may increase, and detection may become delayed.

In a real SOC system, this would be monitored using consumer lag metrics.

### How does tracing help debug pipeline behavior?

Tracing helps show what happened inside the pipeline for each event or operation.

Instead of only seeing the final output, tracing can show intermediate stages and timing information. This helps answer questions such as:

* Did the consumer receive the event?
* Did classification happen?
* Did storage happen?
* Which stage was slow?
* Where did an error occur?

This is especially useful in distributed systems where different components run in different containers or services.

### Which pipeline stages could be scaled independently?

Several stages could be scaled independently:

* Producers could be scaled if more event sources are needed.
* Kafka could be scaled to handle more topics, partitions, or message volume.
* Consumers / classifiers could be scaled if event processing becomes too slow.
* Storage could be scaled if the amount of classified output grows.
* Statistics or analytics jobs could be scaled separately from real-time ingestion.

The most important scaling point is usually the consumer / classifier, because classification can become expensive when the number of events grows.

### How would this pipeline change in a real SOC system?

In a real SOC system, the pipeline would be larger and more robust.

Instead of synthetic notebook-generated events, events would come from real telemetry sources such as endpoint logs, authentication logs, firewall logs, cloud audit logs, IDS alerts, and SIEM data.

The classifier would probably use more advanced logic or machine learning models, and results would be sent to a SIEM, alerting system, case management system, or dashboard.

A real system would also need:

* authentication and access control,
* reliable storage,
* monitoring and alerting,
* error handling,
* schema validation,
* scaling and partitioning,
* retention policies,
* security controls for sensitive data.

This lab demonstrates a simplified version of the same idea: cybersecurity events flow through a pipeline, are classified, stored, and analyzed.
