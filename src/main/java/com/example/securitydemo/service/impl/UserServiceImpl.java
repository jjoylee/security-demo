package com.example.securitydemo.service.impl;

import com.example.securitydemo.domain.Account;
import com.example.securitydemo.repository.UserRepository;
import com.example.securitydemo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
