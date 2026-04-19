class RewardFunction:
    """
    Calculates RL reward/penalty for a detection outcome.
    Used to weight training samples during adaptation.

    Positive reward: detected + correctly classified + responded appropriately
    Negative reward (penalty): false positive OR missed threat
    """

    def calculate(self, outcome: dict) -> float:
        reward = 0.0

        # True positive: correctly detected and classified
        if outcome.get('true_positive'):
            reward += 1.0
            # Bonus for fast detection
            detection_ms = outcome.get('detection_ms', 5000)
            if detection_ms < 1000:
                reward += 0.5
            elif detection_ms < 3000:
                reward += 0.2

        # Penalty for false positive (unnecessarily alarmed user)
        if outcome.get('false_positive'):
            reward -= 0.5

        # Penalty for missed threat (false negative — worst outcome)
        if outcome.get('false_negative'):
            reward -= 2.0

        # Bonus if response matched severity appropriately
        if outcome.get('correct_response'):
            reward += 0.3

        return max(-3.0, min(3.0, reward))

    def weight_from_reward(self, reward: float) -> float:
        """Convert reward to sample weight for retraining."""
        return max(0.1, (reward + 3.0) / 6.0)
