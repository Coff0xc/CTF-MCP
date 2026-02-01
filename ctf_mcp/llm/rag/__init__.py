"""
RAG (Retrieval-Augmented Generation) Module

Connects the KnowledgeBase to the LLM agent.
"""

from .retriever import KnowledgeRetriever

__all__ = ["KnowledgeRetriever"]
