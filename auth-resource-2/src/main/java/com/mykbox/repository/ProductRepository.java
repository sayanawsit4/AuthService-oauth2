package com.mykbox.repository;

import com.mykbox.domain.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProductRepository extends JpaRepository<Product,Long> {

    Product findByNameLike(String name);
    List<Product> findAll();
}




