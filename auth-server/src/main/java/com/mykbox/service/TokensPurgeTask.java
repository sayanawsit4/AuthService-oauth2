package com.mykbox.service;

import com.mykbox.repository.TokenRepository;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.Instant;
import java.util.Date;

@Service
@Transactional
public class TokensPurgeTask {

    private static final Logger LOGGER = Logger.getLogger(TokensPurgeTask.class);

    @Autowired
    private TokenRepository tokenRepository;

    @Scheduled(cron = "${purge.cron.expression}")
    public void purgeExpired() {
        LOGGER.info("running token delete task");
        Date now = Date.from(Instant.now());
        tokenRepository.deleteAllExpiredSince(now);
    }
}