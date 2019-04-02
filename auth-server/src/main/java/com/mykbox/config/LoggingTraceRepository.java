package com.mykbox.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.trace.InMemoryTraceRepository;
import org.springframework.boot.actuate.trace.Trace;
import org.springframework.boot.actuate.trace.TraceRepository;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;


@Component
public class LoggingTraceRepository implements TraceRepository {

    private static final Logger LOG = LoggerFactory.getLogger(LoggingTraceRepository.class);
    private final TraceRepository delegate = new InMemoryTraceRepository();

    @Override
    public List<Trace> findAll() {
        return delegate.findAll();
    }

    @Override
    public void add(Map<String, Object> traceInfo) {
        LOG.info(traceInfo.toString());
        this.delegate.add(traceInfo);
    }
}
